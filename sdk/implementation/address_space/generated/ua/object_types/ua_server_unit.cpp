// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_unit.h"

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

struct ServerUnitTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ServerUnitType};
  }

  static QualifiedName alternative_units_browse_name()
  {
    return QualifiedName{0, "AlternativeUnits"};
  }

  static QualifiedName conversion_limit_browse_name()
  {
    return QualifiedName{0, "ConversionLimit"};
  }

  static QualifiedName symbol_browse_name()
  {
    return QualifiedName{0, "Symbol"};
  }

  static QualifiedName unit_system_browse_name()
  {
    return QualifiedName{0, "UnitSystem"};
  }

  static QualifiedName discipline_browse_name()
  {
    return QualifiedName{0, "Discipline"};
  }
};

}  // namespace

ServerUnit::ServerUnit(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerUnit::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerUnitTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerUnitResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerUnitResult{
        ServerUnit{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

ServerUnitResult ServerUnit::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerUnitResult>(addressSpace.executor(),
      [&](std::function<void(ServerUnitResult)> complete)
      {
        ServerUnit::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerUnit ServerUnit::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ServerUnit::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ServerUnit::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerUnitType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ServerUnitTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerUnitResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerUnitResult{::ua::detail::address_space_gone("ServerUnit")});
        return;
      }
      complete(ServerUnit{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerUnitResult ServerUnit::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerUnitResult>(addressSpace.executor(),
      [&](std::function<void(ServerUnitResult)> complete)
      {
        ServerUnit::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerUnit ServerUnit::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerUnit::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void ServerUnit::find_property_async(
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
    "ServerUnit",
    std::move(complete));
}

// --- Property accessors ---

void ServerUnit::conversion_limit_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerUnitTypeTraits::conversion_limit_browse_name(), std::move(complete));
}

PropertyResult ServerUnit::try_conversion_limit_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { conversion_limit_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerUnit::conversion_limit_property_sync() const
{
  return ::ua::detail::good_value(try_conversion_limit_property_sync());
}

void ServerUnit::symbol_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerUnitTypeTraits::symbol_browse_name(), std::move(complete));
}

PropertyResult ServerUnit::try_symbol_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { symbol_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerUnit::symbol_property_sync() const
{
  return ::ua::detail::good_value(try_symbol_property_sync());
}

void ServerUnit::unit_system_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerUnitTypeTraits::unit_system_browse_name(), std::move(complete));
}

PropertyResult ServerUnit::try_unit_system_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { unit_system_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerUnit::unit_system_property_sync() const
{
  return ::ua::detail::good_value(try_unit_system_property_sync());
}

void ServerUnit::discipline_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerUnitTypeTraits::discipline_browse_name(), std::move(complete));
}

PropertyResult ServerUnit::try_discipline_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { discipline_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerUnit::discipline_property_sync() const
{
  return ::ua::detail::good_value(try_discipline_property_sync());
}

// --- Typed value read shortcuts ---

void ServerUnit::read_symbol_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::symbol_browse_name(),
    &Variant::is_localized_text,
    {"ServerUnit", "symbol", "ServerUnit::read_symbol_async"},
    std::move(complete));
}

LocalizedTextResult ServerUnit::try_read_symbol_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_symbol_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText ServerUnit::read_symbol_sync() const
{
  return ::ua::detail::good_value(try_read_symbol_sync());
}

void ServerUnit::read_unit_system_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::unit_system_browse_name(),
    &Variant::is_string,
    {"ServerUnit", "unit_system", "ServerUnit::read_unit_system_async"},
    std::move(complete));
}

StringResult ServerUnit::try_read_unit_system_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_unit_system_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ServerUnit::read_unit_system_sync() const
{
  return ::ua::detail::good_value(try_read_unit_system_sync());
}

void ServerUnit::read_discipline_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::discipline_browse_name(),
    &Variant::is_string,
    {"ServerUnit", "discipline", "ServerUnit::read_discipline_async"},
    std::move(complete));
}

StringResult ServerUnit::try_read_discipline_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_discipline_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ServerUnit::read_discipline_sync() const
{
  return ::ua::detail::good_value(try_read_discipline_sync());
}

// --- Typed value write shortcuts ---

void ServerUnit::write_symbol_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::symbol_browse_name(),
    "ServerUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerUnit::try_write_symbol_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_symbol_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerUnit::write_symbol_sync(LocalizedText value) const
{
  try_write_symbol_sync(value).value();
}

void ServerUnit::write_unit_system_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::unit_system_browse_name(),
    "ServerUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerUnit::try_write_unit_system_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_unit_system_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerUnit::write_unit_system_sync(String value) const
{
  try_write_unit_system_sync(value).value();
}

void ServerUnit::write_discipline_async(String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerUnitTypeTraits::discipline_browse_name(),
    "ServerUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerUnit::try_write_discipline_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_discipline_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerUnit::write_discipline_sync(String value) const
{
  try_write_discipline_sync(value).value();
}

// --- Child-object accessors ---

void ServerUnit::alternative_units_async(std::function<void(BaseObjectResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BaseObjectResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<BaseObject>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerUnitTypeTraits::alternative_units_browse_name(),
    "ServerUnit",
    std::move(complete));
}

BaseObjectResult ServerUnit::try_alternative_units_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BaseObjectResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BaseObjectResult)> complete) { alternative_units_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

BaseObject ServerUnit::alternative_units_sync() const
{
  return ::ua::detail::good_value(try_alternative_units_sync());
}

}  // namespace ua
