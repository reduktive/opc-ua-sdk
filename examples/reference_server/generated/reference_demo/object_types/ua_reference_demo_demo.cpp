// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reference_demo_demo.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_reference_demo_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_reference_demo_namespace_uri.h"
#include "ua_namespace_array.h"

namespace ua::reference_demo
{
namespace
{

struct DemoTypeTraits
{
  static NodeId type_definition_id(const AddressSpace& addressSpace)
  {
    return NodeId{addressSpace.namespace_array().get_namespace_index(specNamespaceUri),
      static_cast<uint32_t>(ObjectTypeId::DemoType)};
  }

  static QualifiedName uptime_seconds_browse_name()
  {
    return QualifiedName{0, "UptimeSeconds"};
  }

  static QualifiedName setpoint_browse_name()
  {
    return QualifiedName{0, "Setpoint"};
  }

  static QualifiedName divide_browse_name()
  {
    return QualifiedName{0, "Divide"};
  }
};

}  // namespace

Demo::Demo(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void Demo::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    DemoTypeTraits::type_definition_id(addressSpace),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(DemoResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(DemoResult{
        Demo{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

DemoResult Demo::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DemoResult>(addressSpace.executor(),
      [&](std::function<void(DemoResult)> complete)
      { Demo::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Demo Demo::create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void Demo::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void Demo::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // DemoType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    DemoTypeTraits::type_definition_id(addressSpace),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(DemoResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(DemoResult{::ua::detail::address_space_gone("Demo")});
        return;
      }
      complete(Demo{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

DemoResult Demo::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DemoResult>(addressSpace.executor(),
      [&](std::function<void(DemoResult)> complete)
      { Demo::attach_async(std::move(addressSpace), existingInstance, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Demo Demo::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void Demo::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void Demo::divide_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{::ua::ReferenceTypeId::HasComponent},
    QualifiedName{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), "Divide"},
    std::move(complete));
}

MethodAccessorResult Demo::try_divide_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete) { divide_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Demo::divide_method_sync() const
{
  return ::ua::detail::good_value(try_divide_method_sync());
}

// --- Method handler registration ---

void Demo::set_divide_handler_async(
  DivideHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Demo", "Demo::set_divide_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t, int32_t>, std::tuple<int32_t>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const int32_t& in0, const int32_t& in1) -> MethodResult<int32_t>
      {
        DivideInputArguments typedIn{.numerator = in0, .divisor = in1};
        return detail::method_result_from_struct<int32_t>(handler(call, typedIn),
          [](const DivideOutputArguments& out) { return std::tuple<int32_t>{out.quotient}; });
      },
      Inputs<int32_t, int32_t>{{Arg<int32_t>{.name = "numerator"}, Arg<int32_t>{.name = "divisor"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      QualifiedName{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), "Divide"},
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Demo::try_set_divide_handler_sync(DivideHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_divide_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Demo::set_divide_handler_sync(DivideHandler handler) const
{
  try_set_divide_handler_sync(std::move(handler)).value();
}

void Demo::set_divide_handler_async(
  DivideAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Demo", "Demo::set_divide_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<int32_t, int32_t>, std::tuple<int32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const int32_t& in0,
        const int32_t& in1,
        MethodResultCallback<int32_t>
          complete)
      {
        DivideInputArguments typedIn{.numerator = in0, .divisor = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<DivideOutputArguments>(
            std::move(complete),
            [](const DivideOutputArguments& out) { return std::tuple<int32_t>{out.quotient}; },
            logger,
            call.method_id()));
      },
      Inputs<int32_t, int32_t>{{Arg<int32_t>{.name = "numerator"}, Arg<int32_t>{.name = "divisor"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      QualifiedName{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), "Divide"},
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Demo::try_set_divide_handler_sync(DivideAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_divide_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Demo::set_divide_handler_sync(DivideAsyncHandler handler) const
{
  try_set_divide_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void Demo::uptime_seconds_async(std::function<void(::ua::BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(::ua::BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<::ua::BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{::ua::ReferenceTypeId::HasComponent},
    QualifiedName{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), "UptimeSeconds"},
    "Demo",
    std::move(complete));
}

::ua::BaseDataVariableResult Demo::try_uptime_seconds_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<::ua::BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(::ua::BaseDataVariableResult)> complete)
      { uptime_seconds_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

::ua::BaseDataVariable Demo::uptime_seconds_sync() const
{
  return ::ua::detail::good_value(try_uptime_seconds_sync());
}

void Demo::setpoint_async(std::function<void(::ua::BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(::ua::BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<::ua::BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{::ua::ReferenceTypeId::HasComponent},
    QualifiedName{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), "Setpoint"},
    "Demo",
    std::move(complete));
}

::ua::BaseDataVariableResult Demo::try_setpoint_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<::ua::BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(::ua::BaseDataVariableResult)> complete)
      { setpoint_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

::ua::BaseDataVariable Demo::setpoint_sync() const
{
  return ::ua::detail::good_value(try_setpoint_sync());
}

}  // namespace ua::reference_demo
