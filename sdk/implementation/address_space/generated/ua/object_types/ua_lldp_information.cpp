// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_lldp_information.h"

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

struct LldpInformationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LldpInformationType};
  }

  static QualifiedName remote_statistics_browse_name()
  {
    return QualifiedName{0, "RemoteStatistics"};
  }

  static QualifiedName local_system_data_browse_name()
  {
    return QualifiedName{0, "LocalSystemData"};
  }

  static QualifiedName ports_browse_name()
  {
    return QualifiedName{0, "Ports"};
  }
};

}  // namespace

LldpInformation::LldpInformation(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LldpInformation::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LldpInformationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LldpInformationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LldpInformationResult{
        LldpInformation{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

LldpInformationResult LldpInformation::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpInformationResult>(addressSpace.executor(),
      [&](std::function<void(LldpInformationResult)> complete)
      {
        LldpInformation::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpInformation LldpInformation::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LldpInformation::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LldpInformation::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LldpInformationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LldpInformationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LldpInformationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LldpInformationResult{::ua::detail::address_space_gone("LldpInformation")});
        return;
      }
      complete(LldpInformation{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LldpInformationResult LldpInformation::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpInformationResult>(addressSpace.executor(),
      [&](std::function<void(LldpInformationResult)> complete)
      {
        LldpInformation::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpInformation LldpInformation::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LldpInformation::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void LldpInformation::remote_statistics_async(
  std::function<void(LldpRemoteStatisticsResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LldpRemoteStatisticsResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<LldpRemoteStatistics>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpInformationTypeTraits::remote_statistics_browse_name(),
    "LldpInformation",
    std::move(complete));
}

LldpRemoteStatisticsResult LldpInformation::try_remote_statistics_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpRemoteStatisticsResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LldpRemoteStatisticsResult)> complete)
      { remote_statistics_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpRemoteStatistics LldpInformation::remote_statistics_sync() const
{
  return ::ua::detail::good_value(try_remote_statistics_sync());
}

void LldpInformation::local_system_data_async(
  std::function<void(LldpLocalSystemResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LldpLocalSystemResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<LldpLocalSystem>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpInformationTypeTraits::local_system_data_browse_name(),
    "LldpInformation",
    std::move(complete));
}

LldpLocalSystemResult LldpInformation::try_local_system_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpLocalSystemResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LldpLocalSystemResult)> complete)
      { local_system_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpLocalSystem LldpInformation::local_system_data_sync() const
{
  return ::ua::detail::good_value(try_local_system_data_sync());
}

void LldpInformation::ports_async(std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpInformationTypeTraits::ports_browse_name(),
    "LldpInformation",
    std::move(complete));
}

FolderResult LldpInformation::try_ports_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FolderResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FolderResult)> complete) { ports_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Folder LldpInformation::ports_sync() const
{
  return ::ua::detail::good_value(try_ports_sync());
}

}  // namespace ua
