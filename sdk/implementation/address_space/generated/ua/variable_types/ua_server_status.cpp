// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_status.h"

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

struct ServerStatusTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::ServerStatusType};
  }

  static QualifiedName start_time_browse_name()
  {
    return QualifiedName{0, "StartTime"};
  }

  static QualifiedName current_time_browse_name()
  {
    return QualifiedName{0, "CurrentTime"};
  }

  static QualifiedName state_browse_name()
  {
    return QualifiedName{0, "State"};
  }

  static QualifiedName build_info_browse_name()
  {
    return QualifiedName{0, "BuildInfo"};
  }

  static QualifiedName seconds_till_shutdown_browse_name()
  {
    return QualifiedName{0, "SecondsTillShutdown"};
  }

  static QualifiedName shutdown_reason_browse_name()
  {
    return QualifiedName{0, "ShutdownReason"};
  }
};

}  // namespace

ServerStatus::ServerStatus(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerStatus::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerStatusTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerStatusResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerStatusResult{
        ServerStatus{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

ServerStatusResult ServerStatus::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerStatusResult>(addressSpace.executor(),
      [&](std::function<void(ServerStatusResult)> complete)
      {
        ServerStatus::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerStatus ServerStatus::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void ServerStatus::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void ServerStatus::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerStatusType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ServerStatusTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerStatusResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerStatusResult{::ua::detail::address_space_gone("ServerStatus")});
        return;
      }
      complete(ServerStatus{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerStatusResult ServerStatus::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerStatusResult>(addressSpace.executor(),
      [&](std::function<void(ServerStatusResult)> complete)
      {
        ServerStatus::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerStatus ServerStatus::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerStatus::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void ServerStatus::start_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerStatusTypeTraits::start_time_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BaseDataVariableResult ServerStatus::try_start_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { start_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ServerStatus::start_time_sync() const
{
  return ::ua::detail::good_value(try_start_time_sync());
}

void ServerStatus::current_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerStatusTypeTraits::current_time_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BaseDataVariableResult ServerStatus::try_current_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { current_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ServerStatus::current_time_sync() const
{
  return ::ua::detail::good_value(try_current_time_sync());
}

void ServerStatus::state_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerStatusTypeTraits::state_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BaseDataVariableResult ServerStatus::try_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ServerStatus::state_sync() const
{
  return ::ua::detail::good_value(try_state_sync());
}

void ServerStatus::build_info_async(std::function<void(BuildInfoVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BuildInfoVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BuildInfoVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerStatusTypeTraits::build_info_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BuildInfoVariableResult ServerStatus::try_build_info_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BuildInfoVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BuildInfoVariableResult)> complete) { build_info_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BuildInfoVariable ServerStatus::build_info_sync() const
{
  return ::ua::detail::good_value(try_build_info_sync());
}

void ServerStatus::seconds_till_shutdown_async(
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
    ServerStatusTypeTraits::seconds_till_shutdown_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BaseDataVariableResult ServerStatus::try_seconds_till_shutdown_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { seconds_till_shutdown_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ServerStatus::seconds_till_shutdown_sync() const
{
  return ::ua::detail::good_value(try_seconds_till_shutdown_sync());
}

void ServerStatus::shutdown_reason_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerStatusTypeTraits::shutdown_reason_browse_name(),
    "ServerStatus",
    std::move(complete));
}

BaseDataVariableResult ServerStatus::try_shutdown_reason_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { shutdown_reason_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable ServerStatus::shutdown_reason_sync() const
{
  return ::ua::detail::good_value(try_shutdown_reason_sync());
}

}  // namespace ua
