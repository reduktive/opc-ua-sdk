// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_lldp_remote_system.h"

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

struct LldpRemoteSystemTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LldpRemoteSystemType};
  }

  static QualifiedName time_mark_browse_name()
  {
    return QualifiedName{0, "TimeMark"};
  }

  static QualifiedName remote_index_browse_name()
  {
    return QualifiedName{0, "RemoteIndex"};
  }

  static QualifiedName chassis_id_subtype_browse_name()
  {
    return QualifiedName{0, "ChassisIdSubtype"};
  }

  static QualifiedName chassis_id_browse_name()
  {
    return QualifiedName{0, "ChassisId"};
  }

  static QualifiedName port_id_subtype_browse_name()
  {
    return QualifiedName{0, "PortIdSubtype"};
  }

  static QualifiedName port_id_browse_name()
  {
    return QualifiedName{0, "PortId"};
  }

  static QualifiedName port_description_browse_name()
  {
    return QualifiedName{0, "PortDescription"};
  }

  static QualifiedName system_name_browse_name()
  {
    return QualifiedName{0, "SystemName"};
  }

  static QualifiedName system_description_browse_name()
  {
    return QualifiedName{0, "SystemDescription"};
  }

  static QualifiedName system_capabilities_supported_browse_name()
  {
    return QualifiedName{0, "SystemCapabilitiesSupported"};
  }

  static QualifiedName system_capabilities_enabled_browse_name()
  {
    return QualifiedName{0, "SystemCapabilitiesEnabled"};
  }

  static QualifiedName remote_changes_browse_name()
  {
    return QualifiedName{0, "RemoteChanges"};
  }

  static QualifiedName remote_too_many_neighbors_browse_name()
  {
    return QualifiedName{0, "RemoteTooManyNeighbors"};
  }

  static QualifiedName management_address_browse_name()
  {
    return QualifiedName{0, "ManagementAddress"};
  }

  static QualifiedName remote_unknown_tlv_browse_name()
  {
    return QualifiedName{0, "RemoteUnknownTlv"};
  }
};

}  // namespace

LldpRemoteSystem::LldpRemoteSystem(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LldpRemoteSystem::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LldpRemoteSystemTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LldpRemoteSystemResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LldpRemoteSystemResult{
        LldpRemoteSystem{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

LldpRemoteSystemResult LldpRemoteSystem::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpRemoteSystemResult>(addressSpace.executor(),
      [&](std::function<void(LldpRemoteSystemResult)> complete)
      {
        LldpRemoteSystem::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpRemoteSystem LldpRemoteSystem::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LldpRemoteSystem::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LldpRemoteSystem::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LldpRemoteSystemType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LldpRemoteSystemTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LldpRemoteSystemResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LldpRemoteSystemResult{::ua::detail::address_space_gone("LldpRemoteSystem")});
        return;
      }
      complete(LldpRemoteSystem{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LldpRemoteSystemResult LldpRemoteSystem::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpRemoteSystemResult>(addressSpace.executor(),
      [&](std::function<void(LldpRemoteSystemResult)> complete)
      {
        LldpRemoteSystem::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpRemoteSystem LldpRemoteSystem::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LldpRemoteSystem::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void LldpRemoteSystem::time_mark_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpRemoteSystemTypeTraits::time_mark_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_time_mark_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { time_mark_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::time_mark_sync() const
{
  return ::ua::detail::good_value(try_time_mark_sync());
}

void LldpRemoteSystem::remote_index_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpRemoteSystemTypeTraits::remote_index_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_remote_index_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { remote_index_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::remote_index_sync() const
{
  return ::ua::detail::good_value(try_remote_index_sync());
}

void LldpRemoteSystem::chassis_id_subtype_async(
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
    LldpRemoteSystemTypeTraits::chassis_id_subtype_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_chassis_id_subtype_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { chassis_id_subtype_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::chassis_id_subtype_sync() const
{
  return ::ua::detail::good_value(try_chassis_id_subtype_sync());
}

void LldpRemoteSystem::chassis_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpRemoteSystemTypeTraits::chassis_id_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_chassis_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { chassis_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::chassis_id_sync() const
{
  return ::ua::detail::good_value(try_chassis_id_sync());
}

void LldpRemoteSystem::port_id_subtype_async(
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
    LldpRemoteSystemTypeTraits::port_id_subtype_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_port_id_subtype_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { port_id_subtype_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::port_id_subtype_sync() const
{
  return ::ua::detail::good_value(try_port_id_subtype_sync());
}

void LldpRemoteSystem::port_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpRemoteSystemTypeTraits::port_id_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_port_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { port_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::port_id_sync() const
{
  return ::ua::detail::good_value(try_port_id_sync());
}

void LldpRemoteSystem::port_description_async(
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
    LldpRemoteSystemTypeTraits::port_description_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_port_description_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { port_description_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::port_description_sync() const
{
  return ::ua::detail::good_value(try_port_description_sync());
}

void LldpRemoteSystem::system_name_async(std::function<void(BaseDataVariableResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseDataVariableResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseDataVariable>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpRemoteSystemTypeTraits::system_name_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_system_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete) { system_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::system_name_sync() const
{
  return ::ua::detail::good_value(try_system_name_sync());
}

void LldpRemoteSystem::system_description_async(
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
    LldpRemoteSystemTypeTraits::system_description_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_system_description_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { system_description_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::system_description_sync() const
{
  return ::ua::detail::good_value(try_system_description_sync());
}

void LldpRemoteSystem::system_capabilities_supported_async(
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
    LldpRemoteSystemTypeTraits::system_capabilities_supported_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_system_capabilities_supported_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { system_capabilities_supported_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::system_capabilities_supported_sync() const
{
  return ::ua::detail::good_value(try_system_capabilities_supported_sync());
}

void LldpRemoteSystem::system_capabilities_enabled_async(
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
    LldpRemoteSystemTypeTraits::system_capabilities_enabled_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_system_capabilities_enabled_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { system_capabilities_enabled_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::system_capabilities_enabled_sync() const
{
  return ::ua::detail::good_value(try_system_capabilities_enabled_sync());
}

void LldpRemoteSystem::remote_changes_async(
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
    LldpRemoteSystemTypeTraits::remote_changes_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_remote_changes_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_changes_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::remote_changes_sync() const
{
  return ::ua::detail::good_value(try_remote_changes_sync());
}

void LldpRemoteSystem::remote_too_many_neighbors_async(
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
    LldpRemoteSystemTypeTraits::remote_too_many_neighbors_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_remote_too_many_neighbors_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_too_many_neighbors_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::remote_too_many_neighbors_sync() const
{
  return ::ua::detail::good_value(try_remote_too_many_neighbors_sync());
}

void LldpRemoteSystem::management_address_async(
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
    LldpRemoteSystemTypeTraits::management_address_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_management_address_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { management_address_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::management_address_sync() const
{
  return ::ua::detail::good_value(try_management_address_sync());
}

void LldpRemoteSystem::remote_unknown_tlv_async(
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
    LldpRemoteSystemTypeTraits::remote_unknown_tlv_browse_name(),
    "LldpRemoteSystem",
    std::move(complete));
}

BaseDataVariableResult LldpRemoteSystem::try_remote_unknown_tlv_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseDataVariableResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseDataVariableResult)> complete)
      { remote_unknown_tlv_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseDataVariable LldpRemoteSystem::remote_unknown_tlv_sync() const
{
  return ::ua::detail::good_value(try_remote_unknown_tlv_sync());
}

}  // namespace ua
