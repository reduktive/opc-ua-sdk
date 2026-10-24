// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_lldp_local_system.h"

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

struct LldpLocalSystemTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::LldpLocalSystemType};
  }

  static QualifiedName chassis_id_subtype_browse_name()
  {
    return QualifiedName{0, "ChassisIdSubtype"};
  }

  static QualifiedName chassis_id_browse_name()
  {
    return QualifiedName{0, "ChassisId"};
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
};

}  // namespace

LldpLocalSystem::LldpLocalSystem(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void LldpLocalSystem::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    LldpLocalSystemTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(LldpLocalSystemResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(LldpLocalSystemResult{
        LldpLocalSystem{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

LldpLocalSystemResult LldpLocalSystem::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpLocalSystemResult>(addressSpace.executor(),
      [&](std::function<void(LldpLocalSystemResult)> complete)
      {
        LldpLocalSystem::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpLocalSystem LldpLocalSystem::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void LldpLocalSystem::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void LldpLocalSystem::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // LldpLocalSystemType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    LldpLocalSystemTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(LldpLocalSystemResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(LldpLocalSystemResult{::ua::detail::address_space_gone("LldpLocalSystem")});
        return;
      }
      complete(LldpLocalSystem{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

LldpLocalSystemResult LldpLocalSystem::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LldpLocalSystemResult>(addressSpace.executor(),
      [&](std::function<void(LldpLocalSystemResult)> complete)
      {
        LldpLocalSystem::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LldpLocalSystem LldpLocalSystem::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void LldpLocalSystem::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void LldpLocalSystem::find_property_async(
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
    "LldpLocalSystem",
    std::move(complete));
}

// --- Property accessors ---

void LldpLocalSystem::chassis_id_subtype_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpLocalSystemTypeTraits::chassis_id_subtype_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_chassis_id_subtype_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { chassis_id_subtype_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::chassis_id_subtype_property_sync() const
{
  return ::ua::detail::good_value(try_chassis_id_subtype_property_sync());
}

void LldpLocalSystem::chassis_id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpLocalSystemTypeTraits::chassis_id_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_chassis_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { chassis_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::chassis_id_property_sync() const
{
  return ::ua::detail::good_value(try_chassis_id_property_sync());
}

void LldpLocalSystem::system_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpLocalSystemTypeTraits::system_name_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_system_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { system_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::system_name_property_sync() const
{
  return ::ua::detail::good_value(try_system_name_property_sync());
}

void LldpLocalSystem::system_description_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(LldpLocalSystemTypeTraits::system_description_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_system_description_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { system_description_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::system_description_property_sync() const
{
  return ::ua::detail::good_value(try_system_description_property_sync());
}

void LldpLocalSystem::system_capabilities_supported_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    LldpLocalSystemTypeTraits::system_capabilities_supported_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_system_capabilities_supported_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { system_capabilities_supported_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::system_capabilities_supported_property_sync() const
{
  return ::ua::detail::good_value(try_system_capabilities_supported_property_sync());
}

void LldpLocalSystem::system_capabilities_enabled_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    LldpLocalSystemTypeTraits::system_capabilities_enabled_browse_name(), std::move(complete));
}

PropertyResult LldpLocalSystem::try_system_capabilities_enabled_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { system_capabilities_enabled_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property LldpLocalSystem::system_capabilities_enabled_property_sync() const
{
  return ::ua::detail::good_value(try_system_capabilities_enabled_property_sync());
}

// --- Typed value read shortcuts ---

void LldpLocalSystem::read_chassis_id_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::chassis_id_browse_name(),
    &Variant::is_string,
    {"LldpLocalSystem", "chassis_id", "LldpLocalSystem::read_chassis_id_async"},
    std::move(complete));
}

StringResult LldpLocalSystem::try_read_chassis_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_chassis_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpLocalSystem::read_chassis_id_sync() const
{
  return ::ua::detail::good_value(try_read_chassis_id_sync());
}

void LldpLocalSystem::read_system_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::system_name_browse_name(),
    &Variant::is_string,
    {"LldpLocalSystem", "system_name", "LldpLocalSystem::read_system_name_async"},
    std::move(complete));
}

StringResult LldpLocalSystem::try_read_system_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_system_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpLocalSystem::read_system_name_sync() const
{
  return ::ua::detail::good_value(try_read_system_name_sync());
}

void LldpLocalSystem::read_system_description_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::system_description_browse_name(),
    &Variant::is_string,
    {"LldpLocalSystem", "system_description", "LldpLocalSystem::read_system_description_async"},
    std::move(complete));
}

StringResult LldpLocalSystem::try_read_system_description_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_system_description_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String LldpLocalSystem::read_system_description_sync() const
{
  return ::ua::detail::good_value(try_read_system_description_sync());
}

// --- Typed value write shortcuts ---

void LldpLocalSystem::write_chassis_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::chassis_id_browse_name(),
    "LldpLocalSystem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpLocalSystem::try_write_chassis_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_chassis_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpLocalSystem::write_chassis_id_sync(String value) const
{
  try_write_chassis_id_sync(value).value();
}

void LldpLocalSystem::write_system_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::system_name_browse_name(),
    "LldpLocalSystem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpLocalSystem::try_write_system_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_system_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpLocalSystem::write_system_name_sync(String value) const
{
  try_write_system_name_sync(value).value();
}

void LldpLocalSystem::write_system_description_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    LldpLocalSystemTypeTraits::system_description_browse_name(),
    "LldpLocalSystem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult LldpLocalSystem::try_write_system_description_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_system_description_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void LldpLocalSystem::write_system_description_sync(String value) const
{
  try_write_system_description_sync(value).value();
}

}  // namespace ua
