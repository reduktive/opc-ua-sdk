// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alternative_unit.h"

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

struct AlternativeUnitTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AlternativeUnitType};
  }

  static QualifiedName linear_conversion_browse_name()
  {
    return QualifiedName{0, "LinearConversion"};
  }

  static QualifiedName math_ml_conversion_browse_name()
  {
    return QualifiedName{0, "MathMLConversion"};
  }

  static QualifiedName math_ml_inverse_conversion_browse_name()
  {
    return QualifiedName{0, "MathMLInverseConversion"};
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

AlternativeUnit::AlternativeUnit(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AlternativeUnit::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AlternativeUnitTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AlternativeUnitResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AlternativeUnitResult{
        AlternativeUnit{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AlternativeUnitResult AlternativeUnit::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlternativeUnitResult>(addressSpace.executor(),
      [&](std::function<void(AlternativeUnitResult)> complete)
      {
        AlternativeUnit::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlternativeUnit AlternativeUnit::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AlternativeUnit::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AlternativeUnit::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AlternativeUnitType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AlternativeUnitTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AlternativeUnitResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AlternativeUnitResult{::ua::detail::address_space_gone("AlternativeUnit")});
        return;
      }
      complete(AlternativeUnit{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AlternativeUnitResult AlternativeUnit::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AlternativeUnitResult>(addressSpace.executor(),
      [&](std::function<void(AlternativeUnitResult)> complete)
      {
        AlternativeUnit::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AlternativeUnit AlternativeUnit::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AlternativeUnit::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void AlternativeUnit::find_property_async(
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
    "AlternativeUnit",
    std::move(complete));
}

// --- Property accessors ---

void AlternativeUnit::linear_conversion_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlternativeUnitTypeTraits::linear_conversion_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_linear_conversion_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { linear_conversion_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlternativeUnit::linear_conversion_property_sync() const
{
  return ::ua::detail::good_value(try_linear_conversion_property_sync());
}

void AlternativeUnit::math_ml_conversion_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlternativeUnitTypeTraits::math_ml_conversion_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_math_ml_conversion_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { math_ml_conversion_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlternativeUnit::math_ml_conversion_property_sync() const
{
  return ::ua::detail::good_value(try_math_ml_conversion_property_sync());
}

void AlternativeUnit::math_ml_inverse_conversion_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AlternativeUnitTypeTraits::math_ml_inverse_conversion_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_math_ml_inverse_conversion_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { math_ml_inverse_conversion_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AlternativeUnit::math_ml_inverse_conversion_property_sync() const
{
  return ::ua::detail::good_value(try_math_ml_inverse_conversion_property_sync());
}

void AlternativeUnit::symbol_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlternativeUnitTypeTraits::symbol_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_symbol_property_sync() const noexcept
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

Property AlternativeUnit::symbol_property_sync() const
{
  return ::ua::detail::good_value(try_symbol_property_sync());
}

void AlternativeUnit::unit_system_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlternativeUnitTypeTraits::unit_system_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_unit_system_property_sync() const noexcept
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

Property AlternativeUnit::unit_system_property_sync() const
{
  return ::ua::detail::good_value(try_unit_system_property_sync());
}

void AlternativeUnit::discipline_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AlternativeUnitTypeTraits::discipline_browse_name(), std::move(complete));
}

PropertyResult AlternativeUnit::try_discipline_property_sync() const noexcept
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

Property AlternativeUnit::discipline_property_sync() const
{
  return ::ua::detail::good_value(try_discipline_property_sync());
}

// --- Typed value read shortcuts ---

void AlternativeUnit::read_math_ml_conversion_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::math_ml_conversion_browse_name(),
    &Variant::is_string,
    {"AlternativeUnit", "math_ml_conversion", "AlternativeUnit::read_math_ml_conversion_async"},
    std::move(complete));
}

StringResult AlternativeUnit::try_read_math_ml_conversion_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_math_ml_conversion_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AlternativeUnit::read_math_ml_conversion_sync() const
{
  return ::ua::detail::good_value(try_read_math_ml_conversion_sync());
}

void AlternativeUnit::read_math_ml_inverse_conversion_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::math_ml_inverse_conversion_browse_name(),
    &Variant::is_string,
    {"AlternativeUnit",
      "math_ml_inverse_conversion",
      "AlternativeUnit::read_math_ml_inverse_conversion_async"},
    std::move(complete));
}

StringResult AlternativeUnit::try_read_math_ml_inverse_conversion_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_math_ml_inverse_conversion_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AlternativeUnit::read_math_ml_inverse_conversion_sync() const
{
  return ::ua::detail::good_value(try_read_math_ml_inverse_conversion_sync());
}

void AlternativeUnit::read_symbol_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::symbol_browse_name(),
    &Variant::is_localized_text,
    {"AlternativeUnit", "symbol", "AlternativeUnit::read_symbol_async"},
    std::move(complete));
}

LocalizedTextResult AlternativeUnit::try_read_symbol_sync() const noexcept
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

LocalizedText AlternativeUnit::read_symbol_sync() const
{
  return ::ua::detail::good_value(try_read_symbol_sync());
}

void AlternativeUnit::read_unit_system_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::unit_system_browse_name(),
    &Variant::is_string,
    {"AlternativeUnit", "unit_system", "AlternativeUnit::read_unit_system_async"},
    std::move(complete));
}

StringResult AlternativeUnit::try_read_unit_system_sync() const noexcept
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

String AlternativeUnit::read_unit_system_sync() const
{
  return ::ua::detail::good_value(try_read_unit_system_sync());
}

void AlternativeUnit::read_discipline_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::discipline_browse_name(),
    &Variant::is_string,
    {"AlternativeUnit", "discipline", "AlternativeUnit::read_discipline_async"},
    std::move(complete));
}

StringResult AlternativeUnit::try_read_discipline_sync() const noexcept
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

String AlternativeUnit::read_discipline_sync() const
{
  return ::ua::detail::good_value(try_read_discipline_sync());
}

// --- Typed value write shortcuts ---

void AlternativeUnit::write_math_ml_conversion_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::math_ml_conversion_browse_name(),
    "AlternativeUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlternativeUnit::try_write_math_ml_conversion_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_math_ml_conversion_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlternativeUnit::write_math_ml_conversion_sync(String value) const
{
  try_write_math_ml_conversion_sync(value).value();
}

void AlternativeUnit::write_math_ml_inverse_conversion_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::math_ml_inverse_conversion_browse_name(),
    "AlternativeUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlternativeUnit::try_write_math_ml_inverse_conversion_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_math_ml_inverse_conversion_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AlternativeUnit::write_math_ml_inverse_conversion_sync(String value) const
{
  try_write_math_ml_inverse_conversion_sync(value).value();
}

void AlternativeUnit::write_symbol_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::symbol_browse_name(),
    "AlternativeUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlternativeUnit::try_write_symbol_sync(LocalizedText value) const noexcept
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

void AlternativeUnit::write_symbol_sync(LocalizedText value) const
{
  try_write_symbol_sync(value).value();
}

void AlternativeUnit::write_unit_system_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::unit_system_browse_name(),
    "AlternativeUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlternativeUnit::try_write_unit_system_sync(String value) const noexcept
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

void AlternativeUnit::write_unit_system_sync(String value) const
{
  try_write_unit_system_sync(value).value();
}

void AlternativeUnit::write_discipline_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AlternativeUnitTypeTraits::discipline_browse_name(),
    "AlternativeUnit",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AlternativeUnit::try_write_discipline_sync(String value) const noexcept
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

void AlternativeUnit::write_discipline_sync(String value) const
{
  try_write_discipline_sync(value).value();
}

}  // namespace ua
