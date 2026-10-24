// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_lldp_port_information.h"

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

struct LldpPortInformationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LldpPortInformationType};
  }

  static QualifiedName ietf_base_network_interface_name_browse_name()
  {
    return QualifiedName{0, "IetfBaseNetworkInterfaceName"};
  }

  static QualifiedName dest_mac_address_browse_name()
  {
    return QualifiedName{0, "DestMacAddress"};
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

  static QualifiedName management_address_tx_port_browse_name()
  {
    return QualifiedName{0, "ManagementAddressTxPort"};
  }

  static QualifiedName remote_systems_data_browse_name()
  {
    return QualifiedName{0, "RemoteSystemsData"};
  }
};

}  // namespace

LldpPortInformation::LldpPortInformation(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LldpPortInformation::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LldpPortInformationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LldpPortInformationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LldpPortInformationResult{
        LldpPortInformation{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

LldpPortInformationResult LldpPortInformation::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpPortInformationResult>(addressSpace.executor(),
      [&](std::function<void(LldpPortInformationResult)> complete)
      {
        LldpPortInformation::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpPortInformation LldpPortInformation::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LldpPortInformation::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LldpPortInformation::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LldpPortInformationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LldpPortInformationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LldpPortInformationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LldpPortInformationResult{::ua::detail::address_space_gone("LldpPortInformation")});
        return;
      }
      complete(
        LldpPortInformation{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LldpPortInformationResult LldpPortInformation::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpPortInformationResult>(addressSpace.executor(),
      [&](std::function<void(LldpPortInformationResult)> complete)
      {
        LldpPortInformation::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpPortInformation LldpPortInformation::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LldpPortInformation::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void LldpPortInformation::find_property_async(
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
    "LldpPortInformation",
    std::move(complete));
}

// --- Property accessors ---

void LldpPortInformation::ietf_base_network_interface_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    LldpPortInformationTypeTraits::ietf_base_network_interface_name_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_ietf_base_network_interface_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { ietf_base_network_interface_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::ietf_base_network_interface_name_property_sync() const
{
  return ::ua::detail::good_value(try_ietf_base_network_interface_name_property_sync());
}

void LldpPortInformation::dest_mac_address_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpPortInformationTypeTraits::dest_mac_address_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_dest_mac_address_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { dest_mac_address_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::dest_mac_address_property_sync() const
{
  return ::ua::detail::good_value(try_dest_mac_address_property_sync());
}

void LldpPortInformation::port_id_subtype_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpPortInformationTypeTraits::port_id_subtype_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_port_id_subtype_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { port_id_subtype_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::port_id_subtype_property_sync() const
{
  return ::ua::detail::good_value(try_port_id_subtype_property_sync());
}

void LldpPortInformation::port_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpPortInformationTypeTraits::port_id_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_port_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { port_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::port_id_property_sync() const
{
  return ::ua::detail::good_value(try_port_id_property_sync());
}

void LldpPortInformation::port_description_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpPortInformationTypeTraits::port_description_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_port_description_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { port_description_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::port_description_property_sync() const
{
  return ::ua::detail::good_value(try_port_description_property_sync());
}

void LldpPortInformation::management_address_tx_port_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    LldpPortInformationTypeTraits::management_address_tx_port_browse_name(), std::move(complete));
}

PropertyResult LldpPortInformation::try_management_address_tx_port_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { management_address_tx_port_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpPortInformation::management_address_tx_port_property_sync() const
{
  return ::ua::detail::good_value(try_management_address_tx_port_property_sync());
}

// --- Typed value read shortcuts ---

void LldpPortInformation::read_ietf_base_network_interface_name_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::ietf_base_network_interface_name_browse_name(),
    &Variant::is_string,
    {"LldpPortInformation",
      "ietf_base_network_interface_name",
      "LldpPortInformation::read_ietf_base_network_interface_name_async"},
    std::move(complete));
}

StringResult LldpPortInformation::try_read_ietf_base_network_interface_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_ietf_base_network_interface_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpPortInformation::read_ietf_base_network_interface_name_sync() const
{
  return ::ua::detail::good_value(try_read_ietf_base_network_interface_name_sync());
}

void LldpPortInformation::read_dest_mac_address_async(
  std::function<void(UInt8Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt8Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint8_t>(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::dest_mac_address_browse_name(),
    &Variant::is_uint8,
    {"LldpPortInformation", "dest_mac_address", "LldpPortInformation::read_dest_mac_address_async"},
    std::move(complete));
}

UInt8Result LldpPortInformation::try_read_dest_mac_address_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt8Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt8Result)> complete) { read_dest_mac_address_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint8_t LldpPortInformation::read_dest_mac_address_sync() const
{
  return ::ua::detail::good_value(try_read_dest_mac_address_sync());
}

void LldpPortInformation::read_port_id_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::port_id_browse_name(),
    &Variant::is_string,
    {"LldpPortInformation", "port_id", "LldpPortInformation::read_port_id_async"},
    std::move(complete));
}

StringResult LldpPortInformation::try_read_port_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_port_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpPortInformation::read_port_id_sync() const
{
  return ::ua::detail::good_value(try_read_port_id_sync());
}

void LldpPortInformation::read_port_description_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::port_description_browse_name(),
    &Variant::is_string,
    {"LldpPortInformation", "port_description", "LldpPortInformation::read_port_description_async"},
    std::move(complete));
}

StringResult LldpPortInformation::try_read_port_description_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_port_description_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpPortInformation::read_port_description_sync() const
{
  return ::ua::detail::good_value(try_read_port_description_sync());
}

// --- Typed value write shortcuts ---

void LldpPortInformation::write_ietf_base_network_interface_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::ietf_base_network_interface_name_browse_name(),
    "LldpPortInformation",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpPortInformation::try_write_ietf_base_network_interface_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_ietf_base_network_interface_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpPortInformation::write_ietf_base_network_interface_name_sync(String value) const
{
  try_write_ietf_base_network_interface_name_sync(value).value();
}

void LldpPortInformation::write_dest_mac_address_async(
  uint8_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::dest_mac_address_browse_name(),
    "LldpPortInformation",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpPortInformation::try_write_dest_mac_address_sync(uint8_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_dest_mac_address_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpPortInformation::write_dest_mac_address_sync(uint8_t value) const
{
  try_write_dest_mac_address_sync(value).value();
}

void LldpPortInformation::write_port_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::port_id_browse_name(),
    "LldpPortInformation",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpPortInformation::try_write_port_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_port_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpPortInformation::write_port_id_sync(String value) const
{
  try_write_port_id_sync(value).value();
}

void LldpPortInformation::write_port_description_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpPortInformationTypeTraits::port_description_browse_name(),
    "LldpPortInformation",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpPortInformation::try_write_port_description_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_port_description_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpPortInformation::write_port_description_sync(String value) const
{
  try_write_port_description_sync(value).value();
}

// --- Child-object accessors ---

void LldpPortInformation::remote_systems_data_async(std::function<void(FolderResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(FolderResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Folder>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    LldpPortInformationTypeTraits::remote_systems_data_browse_name(),
    "LldpPortInformation",
    std::move(complete));
}

FolderResult LldpPortInformation::try_remote_systems_data_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FolderResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(FolderResult)> complete) { remote_systems_data_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Folder LldpPortInformation::remote_systems_data_sync() const
{
  return ::ua::detail::good_value(try_remote_systems_data_sync());
}

}  // namespace ua
