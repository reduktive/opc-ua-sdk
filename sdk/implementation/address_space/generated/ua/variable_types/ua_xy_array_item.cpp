// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_xy_array_item.h"

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

struct XYArrayItemTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::XYArrayItemType};
  }

  static QualifiedName x_axis_definition_browse_name()
  {
    return QualifiedName{0, "XAxisDefinition"};
  }

  static QualifiedName instrument_range_browse_name()
  {
    return QualifiedName{0, "InstrumentRange"};
  }

  static QualifiedName eu_range_browse_name()
  {
    return QualifiedName{0, "EURange"};
  }

  static QualifiedName engineering_units_browse_name()
  {
    return QualifiedName{0, "EngineeringUnits"};
  }

  static QualifiedName title_browse_name()
  {
    return QualifiedName{0, "Title"};
  }

  static QualifiedName axis_scale_type_browse_name()
  {
    return QualifiedName{0, "AxisScaleType"};
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

XYArrayItem::XYArrayItem(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void XYArrayItem::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    XYArrayItemTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(XYArrayItemResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(XYArrayItemResult{
        XYArrayItem{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

XYArrayItemResult XYArrayItem::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<XYArrayItemResult>(addressSpace.executor(),
      [&](std::function<void(XYArrayItemResult)> complete)
      {
        XYArrayItem::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

XYArrayItem XYArrayItem::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void XYArrayItem::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void XYArrayItem::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // XYArrayItemType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    XYArrayItemTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(XYArrayItemResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(XYArrayItemResult{::ua::detail::address_space_gone("XYArrayItem")});
        return;
      }
      complete(XYArrayItem{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

XYArrayItemResult XYArrayItem::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<XYArrayItemResult>(addressSpace.executor(),
      [&](std::function<void(XYArrayItemResult)> complete)
      {
        XYArrayItem::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

XYArrayItem XYArrayItem::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void XYArrayItem::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void XYArrayItem::find_property_async(
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
    "XYArrayItem",
    std::move(complete));
}

// --- Property accessors ---

void XYArrayItem::x_axis_definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::x_axis_definition_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_x_axis_definition_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { x_axis_definition_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property XYArrayItem::x_axis_definition_property_sync() const
{
  return ::ua::detail::good_value(try_x_axis_definition_property_sync());
}

void XYArrayItem::instrument_range_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::instrument_range_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_instrument_range_property_sync() const noexcept
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

Property XYArrayItem::instrument_range_property_sync() const
{
  return ::ua::detail::good_value(try_instrument_range_property_sync());
}

void XYArrayItem::eu_range_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::eu_range_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_eu_range_property_sync() const noexcept
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

Property XYArrayItem::eu_range_property_sync() const
{
  return ::ua::detail::good_value(try_eu_range_property_sync());
}

void XYArrayItem::engineering_units_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::engineering_units_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_engineering_units_property_sync() const noexcept
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

Property XYArrayItem::engineering_units_property_sync() const
{
  return ::ua::detail::good_value(try_engineering_units_property_sync());
}

void XYArrayItem::title_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::title_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_title_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { title_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property XYArrayItem::title_property_sync() const
{
  return ::ua::detail::good_value(try_title_property_sync());
}

void XYArrayItem::axis_scale_type_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::axis_scale_type_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_axis_scale_type_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { axis_scale_type_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property XYArrayItem::axis_scale_type_property_sync() const
{
  return ::ua::detail::good_value(try_axis_scale_type_property_sync());
}

void XYArrayItem::definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_definition_property_sync() const noexcept
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

Property XYArrayItem::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void XYArrayItem::value_precision_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(XYArrayItemTypeTraits::value_precision_browse_name(), std::move(complete));
}

PropertyResult XYArrayItem::try_value_precision_property_sync() const noexcept
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

Property XYArrayItem::value_precision_property_sync() const
{
  return ::ua::detail::good_value(try_value_precision_property_sync());
}

// --- Typed value read shortcuts ---

void XYArrayItem::read_title_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::title_browse_name(),
    &Variant::is_localized_text,
    {"XYArrayItem", "title", "XYArrayItem::read_title_async"},
    std::move(complete));
}

LocalizedTextResult XYArrayItem::try_read_title_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_title_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText XYArrayItem::read_title_sync() const
{
  return ::ua::detail::good_value(try_read_title_sync());
}

void XYArrayItem::read_definition_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"XYArrayItem", "definition", "XYArrayItem::read_definition_async"},
    std::move(complete));
}

StringResult XYArrayItem::try_read_definition_sync() const noexcept
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

String XYArrayItem::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void XYArrayItem::read_value_precision_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::value_precision_browse_name(),
    &Variant::is_double,
    {"XYArrayItem", "value_precision", "XYArrayItem::read_value_precision_async"},
    std::move(complete));
}

DoubleResult XYArrayItem::try_read_value_precision_sync() const noexcept
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

double XYArrayItem::read_value_precision_sync() const
{
  return ::ua::detail::good_value(try_read_value_precision_sync());
}

// --- Typed value write shortcuts ---

void XYArrayItem::write_title_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::title_browse_name(),
    "XYArrayItem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult XYArrayItem::try_write_title_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_title_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void XYArrayItem::write_title_sync(LocalizedText value) const
{
  try_write_title_sync(value).value();
}

void XYArrayItem::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::definition_browse_name(),
    "XYArrayItem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult XYArrayItem::try_write_definition_sync(String value) const noexcept
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

void XYArrayItem::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void XYArrayItem::write_value_precision_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    XYArrayItemTypeTraits::value_precision_browse_name(),
    "XYArrayItem",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult XYArrayItem::try_write_value_precision_sync(double value) const noexcept
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

void XYArrayItem::write_value_precision_sync(double value) const
{
  try_write_value_precision_sync(value).value();
}

}  // namespace ua
