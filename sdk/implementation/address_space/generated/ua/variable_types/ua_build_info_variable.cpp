// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_build_info_variable.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>

#include "ua_variabletype_id.h"

namespace ua
{
namespace
{

struct BuildInfoTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::BuildInfoType};
  }

  static QualifiedName product_uri_browse_name()
  {
    return QualifiedName{0, "ProductUri"};
  }

  static QualifiedName manufacturer_name_browse_name()
  {
    return QualifiedName{0, "ManufacturerName"};
  }

  static QualifiedName product_name_browse_name()
  {
    return QualifiedName{0, "ProductName"};
  }

  static QualifiedName software_version_browse_name()
  {
    return QualifiedName{0, "SoftwareVersion"};
  }

  static QualifiedName build_number_browse_name()
  {
    return QualifiedName{0, "BuildNumber"};
  }

  static QualifiedName build_date_browse_name()
  {
    return QualifiedName{0, "BuildDate"};
  }
};

}  // namespace

BuildInfoVariable::BuildInfoVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void BuildInfoVariable::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    BuildInfoTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(BuildInfoVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(BuildInfoVariableResult{
        BuildInfoVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

BuildInfoVariableResult BuildInfoVariable::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BuildInfoVariableResult>(addressSpace.executor(),
      [&](std::function<void(BuildInfoVariableResult)> complete)
      {
        BuildInfoVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BuildInfoVariable BuildInfoVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void BuildInfoVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    VariableInstantiationAttributes{attributes},
    std::move(complete));
}

void BuildInfoVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // BuildInfoType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    BuildInfoTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(BuildInfoVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(BuildInfoVariableResult{::ua::detail::address_space_gone("BuildInfoVariable")});
        return;
      }
      complete(BuildInfoVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

BuildInfoVariableResult BuildInfoVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BuildInfoVariableResult>(addressSpace.executor(),
      [&](std::function<void(BuildInfoVariableResult)> complete)
      {
        BuildInfoVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BuildInfoVariable BuildInfoVariable::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void BuildInfoVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void BuildInfoVariable::product_uri_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    BuildInfoTypeTraits::product_uri_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_product_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { product_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::product_uri_sync() const
{
  return ::ua::detail::good_value(try_product_uri_sync());
}

void BuildInfoVariable::manufacturer_name_async(
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
    BuildInfoTypeTraits::manufacturer_name_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_manufacturer_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { manufacturer_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::manufacturer_name_sync() const
{
  return ::ua::detail::good_value(try_manufacturer_name_sync());
}

void BuildInfoVariable::product_name_async(
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
    BuildInfoTypeTraits::product_name_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_product_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { product_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::product_name_sync() const
{
  return ::ua::detail::good_value(try_product_name_sync());
}

void BuildInfoVariable::software_version_async(
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
    BuildInfoTypeTraits::software_version_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_software_version_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { software_version_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::software_version_sync() const
{
  return ::ua::detail::good_value(try_software_version_sync());
}

void BuildInfoVariable::build_number_async(
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
    BuildInfoTypeTraits::build_number_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_build_number_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { build_number_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::build_number_sync() const
{
  return ::ua::detail::good_value(try_build_number_sync());
}

void BuildInfoVariable::build_date_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    BuildInfoTypeTraits::build_date_browse_name(),
    "BuildInfoVariable",
    std::move(complete));
}

BaseDataVariableResult BuildInfoVariable::try_build_date_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { build_date_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable BuildInfoVariable::build_date_sync() const
{
  return ::ua::detail::good_value(try_build_date_sync());
}

}  // namespace ua
