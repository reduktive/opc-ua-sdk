// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_provisionable_device.h"

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

struct ProvisionableDeviceTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ProvisionableDeviceType};
  }

  static QualifiedName is_singleton_browse_name()
  {
    return QualifiedName{0, "IsSingleton"};
  }

  static QualifiedName request_tickets_browse_name()
  {
    return QualifiedName{0, "RequestTickets"};
  }

  static QualifiedName set_registrar_endpoints_browse_name()
  {
    return QualifiedName{0, "SetRegistrarEndpoints"};
  }
};

}  // namespace

ProvisionableDevice::ProvisionableDevice(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ProvisionableDevice::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ProvisionableDeviceTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ProvisionableDeviceResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ProvisionableDeviceResult{
        ProvisionableDevice{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

ProvisionableDeviceResult ProvisionableDevice::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProvisionableDeviceResult>(addressSpace.executor(),
      [&](std::function<void(ProvisionableDeviceResult)> complete)
      {
        ProvisionableDevice::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProvisionableDevice ProvisionableDevice::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ProvisionableDevice::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ProvisionableDevice::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ProvisionableDeviceType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ProvisionableDeviceTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ProvisionableDeviceResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ProvisionableDeviceResult{::ua::detail::address_space_gone("ProvisionableDevice")});
        return;
      }
      complete(
        ProvisionableDevice{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ProvisionableDeviceResult ProvisionableDevice::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ProvisionableDeviceResult>(addressSpace.executor(),
      [&](std::function<void(ProvisionableDeviceResult)> complete)
      {
        ProvisionableDevice::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ProvisionableDevice ProvisionableDevice::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ProvisionableDevice::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void ProvisionableDevice::request_tickets_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ProvisionableDeviceTypeTraits::request_tickets_browse_name(),
    std::move(complete));
}

MethodAccessorResult ProvisionableDevice::try_request_tickets_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { request_tickets_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ProvisionableDevice::request_tickets_method_sync() const
{
  return ::ua::detail::good_value(try_request_tickets_method_sync());
}

void ProvisionableDevice::set_registrar_endpoints_method_async(
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
    ProvisionableDeviceTypeTraits::set_registrar_endpoints_browse_name(),
    std::move(complete));
}

MethodAccessorResult ProvisionableDevice::try_set_registrar_endpoints_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { set_registrar_endpoints_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ProvisionableDevice::set_registrar_endpoints_method_sync() const
{
  return ::ua::detail::good_value(try_set_registrar_endpoints_method_sync());
}

// --- Common property helper ---

void ProvisionableDevice::find_property_async(
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
    "ProvisionableDevice",
    std::move(complete));
}

// --- Property accessors ---

void ProvisionableDevice::is_singleton_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ProvisionableDeviceTypeTraits::is_singleton_browse_name(), std::move(complete));
}

PropertyResult ProvisionableDevice::try_is_singleton_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { is_singleton_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ProvisionableDevice::is_singleton_property_sync() const
{
  return ::ua::detail::good_value(try_is_singleton_property_sync());
}

// --- Typed value read shortcuts ---

void ProvisionableDevice::read_is_singleton_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ProvisionableDeviceTypeTraits::is_singleton_browse_name(),
    &Variant::is_boolean,
    {"ProvisionableDevice", "is_singleton", "ProvisionableDevice::read_is_singleton_async"},
    std::move(complete));
}

BoolResult ProvisionableDevice::try_read_is_singleton_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_is_singleton_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ProvisionableDevice::read_is_singleton_sync() const
{
  return ::ua::detail::good_value(try_read_is_singleton_sync());
}

// --- Typed value write shortcuts ---

void ProvisionableDevice::write_is_singleton_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ProvisionableDeviceTypeTraits::is_singleton_browse_name(),
    "ProvisionableDevice",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ProvisionableDevice::try_write_is_singleton_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_is_singleton_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProvisionableDevice::write_is_singleton_sync(bool value) const
{
  try_write_is_singleton_sync(value).value();
}

// --- Method handler registration ---

void ProvisionableDevice::set_request_tickets_handler_async(
  RequestTicketsHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ProvisionableDevice",
        "ProvisionableDevice::set_request_tickets_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<Variant>>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<std::vector<Variant>>
      {
        return detail::method_result_from_struct<std::vector<Variant>>(handler(call),
          [](const RequestTicketsOutputArguments& out)
          { return std::tuple<std::vector<Variant>>{out.tickets}; });
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ProvisionableDeviceTypeTraits::request_tickets_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ProvisionableDevice::try_set_request_tickets_handler_sync(
  RequestTicketsHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_request_tickets_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProvisionableDevice::set_request_tickets_handler_sync(RequestTicketsHandler handler) const
{
  try_set_request_tickets_handler_sync(std::move(handler)).value();
}

void ProvisionableDevice::set_request_tickets_handler_async(
  RequestTicketsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ProvisionableDevice",
        "ProvisionableDevice::set_request_tickets_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<std::vector<Variant>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<std::vector<Variant>> complete)
      {
        handler(call,
          detail::struct_method_result_callback<RequestTicketsOutputArguments>(
            std::move(complete),
            [](const RequestTicketsOutputArguments& out)
            { return std::tuple<std::vector<Variant>>{out.tickets}; },
            logger,
            call.method_id()));
      },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ProvisionableDeviceTypeTraits::request_tickets_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ProvisionableDevice::try_set_request_tickets_handler_sync(
  RequestTicketsAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_request_tickets_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProvisionableDevice::set_request_tickets_handler_sync(RequestTicketsAsyncHandler handler) const
{
  try_set_request_tickets_handler_sync(std::move(handler)).value();
}

void ProvisionableDevice::set_set_registrar_endpoints_handler_async(
  SetRegistrarEndpointsHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ProvisionableDevice",
        "ProvisionableDevice::set_set_registrar_endpoints_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Array<Variant>>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Array<Variant>& in0) -> MethodResult<>
      {
        SetRegistrarEndpointsInputArguments typedIn{.registrars = in0.payload()};
        return handler(call, typedIn);
      },
      Inputs<Array<Variant>>{{Arg<Array<Variant>>{.name = "Registrars"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ProvisionableDeviceTypeTraits::set_registrar_endpoints_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ProvisionableDevice::try_set_set_registrar_endpoints_handler_sync(
  SetRegistrarEndpointsHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_registrar_endpoints_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProvisionableDevice::set_set_registrar_endpoints_handler_sync(SetRegistrarEndpointsHandler handler) const
{
  try_set_set_registrar_endpoints_handler_sync(std::move(handler)).value();
}

void ProvisionableDevice::set_set_registrar_endpoints_handler_async(
  SetRegistrarEndpointsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ProvisionableDevice",
        "ProvisionableDevice::set_set_registrar_endpoints_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Array<Variant>>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Array<Variant>& in0, MethodResultCallback<> complete)
      {
        SetRegistrarEndpointsInputArguments typedIn{.registrars = in0.payload()};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Array<Variant>>{{Arg<Array<Variant>>{.name = "Registrars"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ProvisionableDeviceTypeTraits::set_registrar_endpoints_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ProvisionableDevice::try_set_set_registrar_endpoints_handler_sync(
  SetRegistrarEndpointsAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_registrar_endpoints_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ProvisionableDevice::set_set_registrar_endpoints_handler_sync(
  SetRegistrarEndpointsAsyncHandler handler) const
{
  try_set_set_registrar_endpoints_handler_sync(std::move(handler)).value();
}

}  // namespace ua
