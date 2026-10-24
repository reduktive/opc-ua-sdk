// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_lldp_remote_statistics.h"

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

struct LldpRemoteStatisticsTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LldpRemoteStatisticsType};
  }

  static QualifiedName last_change_time_browse_name()
  {
    return QualifiedName{0, "LastChangeTime"};
  }

  static QualifiedName remote_inserts_browse_name()
  {
    return QualifiedName{0, "RemoteInserts"};
  }

  static QualifiedName remote_deletes_browse_name()
  {
    return QualifiedName{0, "RemoteDeletes"};
  }

  static QualifiedName remote_drops_browse_name()
  {
    return QualifiedName{0, "RemoteDrops"};
  }

  static QualifiedName remote_ageouts_browse_name()
  {
    return QualifiedName{0, "RemoteAgeouts"};
  }
};

}  // namespace

LldpRemoteStatistics::LldpRemoteStatistics(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LldpRemoteStatistics::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LldpRemoteStatisticsTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LldpRemoteStatisticsResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LldpRemoteStatisticsResult{
        LldpRemoteStatistics{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

LldpRemoteStatisticsResult LldpRemoteStatistics::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpRemoteStatisticsResult>(addressSpace.executor(),
      [&](std::function<void(LldpRemoteStatisticsResult)> complete)
      {
        LldpRemoteStatistics::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpRemoteStatistics LldpRemoteStatistics::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LldpRemoteStatistics::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LldpRemoteStatistics::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LldpRemoteStatisticsType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LldpRemoteStatisticsTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LldpRemoteStatisticsResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LldpRemoteStatisticsResult{::ua::detail::address_space_gone("LldpRemoteStatistics")});
        return;
      }
      complete(
        LldpRemoteStatistics{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LldpRemoteStatisticsResult LldpRemoteStatistics::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpRemoteStatisticsResult>(addressSpace.executor(),
      [&](std::function<void(LldpRemoteStatisticsResult)> complete)
      {
        LldpRemoteStatistics::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpRemoteStatistics LldpRemoteStatistics::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LldpRemoteStatistics::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void LldpRemoteStatistics::last_change_time_async(
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
    LldpRemoteStatisticsTypeTraits::last_change_time_browse_name(),
    "LldpRemoteStatistics",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteStatistics::try_last_change_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { last_change_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteStatistics::last_change_time_sync() const
{
  return ::ua::detail::good_value(try_last_change_time_sync());
}

void LldpRemoteStatistics::remote_inserts_async(
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
    LldpRemoteStatisticsTypeTraits::remote_inserts_browse_name(),
    "LldpRemoteStatistics",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteStatistics::try_remote_inserts_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_inserts_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteStatistics::remote_inserts_sync() const
{
  return ::ua::detail::good_value(try_remote_inserts_sync());
}

void LldpRemoteStatistics::remote_deletes_async(
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
    LldpRemoteStatisticsTypeTraits::remote_deletes_browse_name(),
    "LldpRemoteStatistics",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteStatistics::try_remote_deletes_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_deletes_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteStatistics::remote_deletes_sync() const
{
  return ::ua::detail::good_value(try_remote_deletes_sync());
}

void LldpRemoteStatistics::remote_drops_async(
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
    LldpRemoteStatisticsTypeTraits::remote_drops_browse_name(),
    "LldpRemoteStatistics",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteStatistics::try_remote_drops_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { remote_drops_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteStatistics::remote_drops_sync() const
{
  return ::ua::detail::good_value(try_remote_drops_sync());
}

void LldpRemoteStatistics::remote_ageouts_async(
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
    LldpRemoteStatisticsTypeTraits::remote_ageouts_browse_name(),
    "LldpRemoteStatistics",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteStatistics::try_remote_ageouts_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_ageouts_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteStatistics::remote_ageouts_sync() const
{
  return ::ua::detail::good_value(try_remote_ageouts_sync());
}

}  // namespace ua
