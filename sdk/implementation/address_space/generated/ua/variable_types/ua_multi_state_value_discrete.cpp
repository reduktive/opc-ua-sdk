// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_multi_state_value_discrete.h"

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

struct MultiStateValueDiscreteTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::MultiStateValueDiscreteType};
  }

  static QualifiedName enum_values_browse_name()
  {
    return QualifiedName{0, "EnumValues"};
  }

  static QualifiedName value_as_text_browse_name()
  {
    return QualifiedName{0, "ValueAsText"};
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

MultiStateValueDiscrete::MultiStateValueDiscrete(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void MultiStateValueDiscrete::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    MultiStateValueDiscreteTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(MultiStateValueDiscreteResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      auto wireAddressSpace = data.addressSpace;
      auto wireNodeId = data.nodeId;
      auto ownedSubtree = std::make_shared<decltype(data.subtree)>(std::move(data.subtree));
      instance_utils::wire_value_as_text_async(std::move(wireAddressSpace),
        std::move(wireNodeId),
        [weakAddressSpace = data.addressSpace.weak(),
          nodeId = std::move(data.nodeId),
          ownedSubtree,
          code,
          complete = std::move(complete)](VoidResult) mutable
        {
          auto wiredAddressSpace = weakAddressSpace.lock();
          if (!wiredAddressSpace)
          {
            complete(
              MultiStateValueDiscreteResult{::ua::detail::address_space_gone("MultiStateValueDiscrete")});
            return;
          }
          complete(MultiStateValueDiscreteResult{
            MultiStateValueDiscrete{
              std::move(*wiredAddressSpace), std::move(nodeId), std::move(*ownedSubtree)},
            code});
        });
    });
}

MultiStateValueDiscreteResult MultiStateValueDiscrete::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MultiStateValueDiscreteResult>(addressSpace.executor(),
      [&](std::function<void(MultiStateValueDiscreteResult)> complete)
      {
        MultiStateValueDiscrete::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MultiStateValueDiscrete MultiStateValueDiscrete::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void MultiStateValueDiscrete::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void MultiStateValueDiscrete::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // MultiStateValueDiscreteType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    MultiStateValueDiscreteTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(MultiStateValueDiscreteResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(MultiStateValueDiscreteResult{::ua::detail::address_space_gone("MultiStateValueDiscrete")});
        return;
      }
      complete(
        MultiStateValueDiscrete{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

MultiStateValueDiscreteResult MultiStateValueDiscrete::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MultiStateValueDiscreteResult>(addressSpace.executor(),
      [&](std::function<void(MultiStateValueDiscreteResult)> complete)
      {
        MultiStateValueDiscrete::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MultiStateValueDiscrete MultiStateValueDiscrete::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void MultiStateValueDiscrete::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void MultiStateValueDiscrete::find_property_async(
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
    "MultiStateValueDiscrete",
    std::move(complete));
}

// --- Property accessors ---

void MultiStateValueDiscrete::enum_values_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(MultiStateValueDiscreteTypeTraits::enum_values_browse_name(), std::move(complete));
}

PropertyResult MultiStateValueDiscrete::try_enum_values_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { enum_values_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateValueDiscrete::enum_values_property_sync() const
{
  return ::ua::detail::good_value(try_enum_values_property_sync());
}

void MultiStateValueDiscrete::value_as_text_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(MultiStateValueDiscreteTypeTraits::value_as_text_browse_name(), std::move(complete));
}

PropertyResult MultiStateValueDiscrete::try_value_as_text_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { value_as_text_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property MultiStateValueDiscrete::value_as_text_property_sync() const
{
  return ::ua::detail::good_value(try_value_as_text_property_sync());
}

void MultiStateValueDiscrete::definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(MultiStateValueDiscreteTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult MultiStateValueDiscrete::try_definition_property_sync() const noexcept
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

Property MultiStateValueDiscrete::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void MultiStateValueDiscrete::value_precision_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(MultiStateValueDiscreteTypeTraits::value_precision_browse_name(), std::move(complete));
}

PropertyResult MultiStateValueDiscrete::try_value_precision_property_sync() const noexcept
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

Property MultiStateValueDiscrete::value_precision_property_sync() const
{
  return ::ua::detail::good_value(try_value_precision_property_sync());
}

// --- Typed value read shortcuts ---

void MultiStateValueDiscrete::read_value_as_text_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::value_as_text_browse_name(),
    &Variant::is_localized_text,
    {"MultiStateValueDiscrete", "value_as_text", "MultiStateValueDiscrete::read_value_as_text_async"},
    std::move(complete));
}

LocalizedTextResult MultiStateValueDiscrete::try_read_value_as_text_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_value_as_text_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText MultiStateValueDiscrete::read_value_as_text_sync() const
{
  return ::ua::detail::good_value(try_read_value_as_text_sync());
}

void MultiStateValueDiscrete::read_definition_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"MultiStateValueDiscrete", "definition", "MultiStateValueDiscrete::read_definition_async"},
    std::move(complete));
}

StringResult MultiStateValueDiscrete::try_read_definition_sync() const noexcept
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

String MultiStateValueDiscrete::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void MultiStateValueDiscrete::read_value_precision_async(
  std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::value_precision_browse_name(),
    &Variant::is_double,
    {"MultiStateValueDiscrete", "value_precision", "MultiStateValueDiscrete::read_value_precision_async"},
    std::move(complete));
}

DoubleResult MultiStateValueDiscrete::try_read_value_precision_sync() const noexcept
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

double MultiStateValueDiscrete::read_value_precision_sync() const
{
  return ::ua::detail::good_value(try_read_value_precision_sync());
}

// --- Typed value write shortcuts ---

void MultiStateValueDiscrete::write_value_as_text_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::value_as_text_browse_name(),
    "MultiStateValueDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateValueDiscrete::try_write_value_as_text_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_value_as_text_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void MultiStateValueDiscrete::write_value_as_text_sync(LocalizedText value) const
{
  try_write_value_as_text_sync(value).value();
}

void MultiStateValueDiscrete::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::definition_browse_name(),
    "MultiStateValueDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateValueDiscrete::try_write_definition_sync(String value) const noexcept
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

void MultiStateValueDiscrete::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void MultiStateValueDiscrete::write_value_precision_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    MultiStateValueDiscreteTypeTraits::value_precision_browse_name(),
    "MultiStateValueDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult MultiStateValueDiscrete::try_write_value_precision_sync(double value) const noexcept
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

void MultiStateValueDiscrete::write_value_precision_sync(double value) const
{
  try_write_value_precision_sync(value).value();
}

}  // namespace ua
