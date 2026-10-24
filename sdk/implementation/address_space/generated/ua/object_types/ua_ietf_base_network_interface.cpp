// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_ietf_base_network_interface.h"

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

struct IetfBaseNetworkInterfaceTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::IetfBaseNetworkInterfaceType};
  }

  static QualifiedName admin_status_browse_name()
  {
    return QualifiedName{0, "AdminStatus"};
  }

  static QualifiedName oper_status_browse_name()
  {
    return QualifiedName{0, "OperStatus"};
  }

  static QualifiedName phys_address_browse_name()
  {
    return QualifiedName{0, "PhysAddress"};
  }

  static QualifiedName speed_browse_name()
  {
    return QualifiedName{0, "Speed"};
  }
};

}  // namespace

IetfBaseNetworkInterface::IetfBaseNetworkInterface(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void IetfBaseNetworkInterface::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    IetfBaseNetworkInterfaceTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(IetfBaseNetworkInterfaceResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(IetfBaseNetworkInterfaceResult{
        IetfBaseNetworkInterface{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

IetfBaseNetworkInterfaceResult IetfBaseNetworkInterface::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<IetfBaseNetworkInterfaceResult>(addressSpace.executor(),
      [&](std::function<void(IetfBaseNetworkInterfaceResult)> complete)
      {
        IetfBaseNetworkInterface::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

IetfBaseNetworkInterface IetfBaseNetworkInterface::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void IetfBaseNetworkInterface::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void IetfBaseNetworkInterface::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // IetfBaseNetworkInterfaceType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    IetfBaseNetworkInterfaceTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(IetfBaseNetworkInterfaceResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          IetfBaseNetworkInterfaceResult{::ua::detail::address_space_gone("IetfBaseNetworkInterface")});
        return;
      }
      complete(
        IetfBaseNetworkInterface{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

IetfBaseNetworkInterfaceResult IetfBaseNetworkInterface::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<IetfBaseNetworkInterfaceResult>(addressSpace.executor(),
      [&](std::function<void(IetfBaseNetworkInterfaceResult)> complete)
      {
        IetfBaseNetworkInterface::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

IetfBaseNetworkInterface IetfBaseNetworkInterface::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void IetfBaseNetworkInterface::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void IetfBaseNetworkInterface::admin_status_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    IetfBaseNetworkInterfaceTypeTraits::admin_status_browse_name(),
    "IetfBaseNetworkInterface",
    std::move(complete));
}

BaseDataVariableResult IetfBaseNetworkInterface::try_admin_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { admin_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable IetfBaseNetworkInterface::admin_status_sync() const
{
  return ::ua::detail::good_value(try_admin_status_sync());
}

void IetfBaseNetworkInterface::oper_status_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    IetfBaseNetworkInterfaceTypeTraits::oper_status_browse_name(),
    "IetfBaseNetworkInterface",
    std::move(complete));
}

BaseDataVariableResult IetfBaseNetworkInterface::try_oper_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { oper_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable IetfBaseNetworkInterface::oper_status_sync() const
{
  return ::ua::detail::good_value(try_oper_status_sync());
}

void IetfBaseNetworkInterface::phys_address_async(
  std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    IetfBaseNetworkInterfaceTypeTraits::phys_address_browse_name(),
    "IetfBaseNetworkInterface",
    std::move(complete));
}

BaseDataVariableResult IetfBaseNetworkInterface::try_phys_address_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { phys_address_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable IetfBaseNetworkInterface::phys_address_sync() const
{
  return ::ua::detail::good_value(try_phys_address_sync());
}

void IetfBaseNetworkInterface::speed_async(std::function<void(AnalogUnitResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(AnalogUnitResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<AnalogUnit>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    IetfBaseNetworkInterfaceTypeTraits::speed_browse_name(),
    "IetfBaseNetworkInterface",
    std::move(complete));
}

AnalogUnitResult IetfBaseNetworkInterface::try_speed_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AnalogUnitResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(AnalogUnitResult)> complete) { speed_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AnalogUnit IetfBaseNetworkInterface::speed_sync() const
{
  return ::ua::detail::good_value(try_speed_sync());
}

}  // namespace ua
