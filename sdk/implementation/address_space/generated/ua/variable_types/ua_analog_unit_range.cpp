// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_analog_unit_range.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>

#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"

namespace ua
{
namespace
{

struct AnalogUnitRangeTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::AnalogUnitRangeType};
  }

  static QualifiedName engineering_units_browse_name()
  {
    return QualifiedName{0, "EngineeringUnits"};
  }

  static QualifiedName eu_range_browse_name()
  {
    return QualifiedName{0, "EURange"};
  }

  static QualifiedName instrument_range_browse_name()
  {
    return QualifiedName{0, "InstrumentRange"};
  }

  static QualifiedName definition_browse_name()
  {
    return QualifiedName{0, "Definition"};
  }

  static QualifiedName value_precision_browse_name()
  {
    return QualifiedName{0, "ValuePrecision"};
  }
};

}  // namespace

AnalogUnitRange::AnalogUnitRange(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AnalogUnitRange::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AnalogUnitRangeTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AnalogUnitRangeResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AnalogUnitRangeResult{
        AnalogUnitRange{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AnalogUnitRangeResult AnalogUnitRange::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AnalogUnitRangeResult>(addressSpace.executor(),
      [&](std::function<void(AnalogUnitRangeResult)> complete)
      {
        AnalogUnitRange::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AnalogUnitRange AnalogUnitRange::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void AnalogUnitRange::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void AnalogUnitRange::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AnalogUnitRangeType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AnalogUnitRangeTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AnalogUnitRangeResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AnalogUnitRangeResult{::ua::detail::address_space_gone("AnalogUnitRange")});
        return;
      }
      complete(AnalogUnitRange{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AnalogUnitRangeResult AnalogUnitRange::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AnalogUnitRangeResult>(addressSpace.executor(),
      [&](std::function<void(AnalogUnitRangeResult)> complete)
      {
        AnalogUnitRange::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AnalogUnitRange AnalogUnitRange::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AnalogUnitRange::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void AnalogUnitRange::find_property_async(
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
    "AnalogUnitRange",
    std::move(complete));
}

// --- Property accessors ---

void AnalogUnitRange::engineering_units_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AnalogUnitRangeTypeTraits::engineering_units_browse_name(), std::move(complete));
}

PropertyResult AnalogUnitRange::try_engineering_units_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { engineering_units_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AnalogUnitRange::engineering_units_property_sync() const
{
  return ::ua::detail::good_value(try_engineering_units_property_sync());
}

void AnalogUnitRange::eu_range_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AnalogUnitRangeTypeTraits::eu_range_browse_name(), std::move(complete));
}

PropertyResult AnalogUnitRange::try_eu_range_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { eu_range_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AnalogUnitRange::eu_range_property_sync() const
{
  return ::ua::detail::good_value(try_eu_range_property_sync());
}

void AnalogUnitRange::instrument_range_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AnalogUnitRangeTypeTraits::instrument_range_browse_name(), std::move(complete));
}

PropertyResult AnalogUnitRange::try_instrument_range_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { instrument_range_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AnalogUnitRange::instrument_range_property_sync() const
{
  return ::ua::detail::good_value(try_instrument_range_property_sync());
}

void AnalogUnitRange::definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AnalogUnitRangeTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult AnalogUnitRange::try_definition_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { definition_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AnalogUnitRange::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void AnalogUnitRange::value_precision_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(AnalogUnitRangeTypeTraits::value_precision_browse_name(), std::move(complete));
}

PropertyResult AnalogUnitRange::try_value_precision_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { value_precision_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AnalogUnitRange::value_precision_property_sync() const
{
  return ::ua::detail::good_value(try_value_precision_property_sync());
}

// --- Typed value read shortcuts ---

void AnalogUnitRange::read_definition_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AnalogUnitRangeTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"AnalogUnitRange", "definition", "AnalogUnitRange::read_definition_async"},
    std::move(complete));
}

StringResult AnalogUnitRange::try_read_definition_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_definition_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AnalogUnitRange::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void AnalogUnitRange::read_value_precision_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    AnalogUnitRangeTypeTraits::value_precision_browse_name(),
    &Variant::is_double,
    {"AnalogUnitRange", "value_precision", "AnalogUnitRange::read_value_precision_async"},
    std::move(complete));
}

DoubleResult AnalogUnitRange::try_read_value_precision_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DoubleResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DoubleResult)> complete) { read_value_precision_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

double AnalogUnitRange::read_value_precision_sync() const
{
  return ::ua::detail::good_value(try_read_value_precision_sync());
}

// --- Typed value write shortcuts ---

void AnalogUnitRange::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AnalogUnitRangeTypeTraits::definition_browse_name(),
    "AnalogUnitRange",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AnalogUnitRange::try_write_definition_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_definition_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AnalogUnitRange::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void AnalogUnitRange::write_value_precision_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AnalogUnitRangeTypeTraits::value_precision_browse_name(),
    "AnalogUnitRange",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AnalogUnitRange::try_write_value_precision_sync(double value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_value_precision_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AnalogUnitRange::write_value_precision_sync(double value) const
{
  try_write_value_precision_sync(value).value();
}

}  // namespace ua
