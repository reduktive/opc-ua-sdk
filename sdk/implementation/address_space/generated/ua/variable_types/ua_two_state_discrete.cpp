// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_two_state_discrete.h"

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

struct TwoStateDiscreteTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::TwoStateDiscreteType};
  }

  static QualifiedName false_state_browse_name()
  {
    return QualifiedName{0, "FalseState"};
  }

  static QualifiedName true_state_browse_name()
  {
    return QualifiedName{0, "TrueState"};
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

TwoStateDiscrete::TwoStateDiscrete(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TwoStateDiscrete::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TwoStateDiscreteTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TwoStateDiscreteResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TwoStateDiscreteResult{
        TwoStateDiscrete{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

TwoStateDiscreteResult TwoStateDiscrete::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateDiscreteResult>(addressSpace.executor(),
      [&](std::function<void(TwoStateDiscreteResult)> complete)
      {
        TwoStateDiscrete::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateDiscrete TwoStateDiscrete::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void TwoStateDiscrete::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void TwoStateDiscrete::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TwoStateDiscreteType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    TwoStateDiscreteTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TwoStateDiscreteResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TwoStateDiscreteResult{::ua::detail::address_space_gone("TwoStateDiscrete")});
        return;
      }
      complete(TwoStateDiscrete{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TwoStateDiscreteResult TwoStateDiscrete::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateDiscreteResult>(addressSpace.executor(),
      [&](std::function<void(TwoStateDiscreteResult)> complete)
      {
        TwoStateDiscrete::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateDiscrete TwoStateDiscrete::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TwoStateDiscrete::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void TwoStateDiscrete::find_property_async(
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
    "TwoStateDiscrete",
    std::move(complete));
}

// --- Property accessors ---

void TwoStateDiscrete::false_state_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateDiscreteTypeTraits::false_state_browse_name(), std::move(complete));
}

PropertyResult TwoStateDiscrete::try_false_state_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { false_state_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateDiscrete::false_state_property_sync() const
{
  return ::ua::detail::good_value(try_false_state_property_sync());
}

void TwoStateDiscrete::true_state_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateDiscreteTypeTraits::true_state_browse_name(), std::move(complete));
}

PropertyResult TwoStateDiscrete::try_true_state_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { true_state_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateDiscrete::true_state_property_sync() const
{
  return ::ua::detail::good_value(try_true_state_property_sync());
}

void TwoStateDiscrete::definition_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateDiscreteTypeTraits::definition_browse_name(), std::move(complete));
}

PropertyResult TwoStateDiscrete::try_definition_property_sync() const noexcept
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

Property TwoStateDiscrete::definition_property_sync() const
{
  return ::ua::detail::good_value(try_definition_property_sync());
}

void TwoStateDiscrete::value_precision_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateDiscreteTypeTraits::value_precision_browse_name(), std::move(complete));
}

PropertyResult TwoStateDiscrete::try_value_precision_property_sync() const noexcept
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

Property TwoStateDiscrete::value_precision_property_sync() const
{
  return ::ua::detail::good_value(try_value_precision_property_sync());
}

// --- Typed value read shortcuts ---

void TwoStateDiscrete::read_false_state_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::false_state_browse_name(),
    &Variant::is_localized_text,
    {"TwoStateDiscrete", "false_state", "TwoStateDiscrete::read_false_state_async"},
    std::move(complete));
}

LocalizedTextResult TwoStateDiscrete::try_read_false_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_false_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText TwoStateDiscrete::read_false_state_sync() const
{
  return ::ua::detail::good_value(try_read_false_state_sync());
}

void TwoStateDiscrete::read_true_state_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::true_state_browse_name(),
    &Variant::is_localized_text,
    {"TwoStateDiscrete", "true_state", "TwoStateDiscrete::read_true_state_async"},
    std::move(complete));
}

LocalizedTextResult TwoStateDiscrete::try_read_true_state_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete) { read_true_state_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText TwoStateDiscrete::read_true_state_sync() const
{
  return ::ua::detail::good_value(try_read_true_state_sync());
}

void TwoStateDiscrete::read_definition_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::definition_browse_name(),
    &Variant::is_string,
    {"TwoStateDiscrete", "definition", "TwoStateDiscrete::read_definition_async"},
    std::move(complete));
}

StringResult TwoStateDiscrete::try_read_definition_sync() const noexcept
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

String TwoStateDiscrete::read_definition_sync() const
{
  return ::ua::detail::good_value(try_read_definition_sync());
}

void TwoStateDiscrete::read_value_precision_async(std::function<void(DoubleResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DoubleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<double>(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::value_precision_browse_name(),
    &Variant::is_double,
    {"TwoStateDiscrete", "value_precision", "TwoStateDiscrete::read_value_precision_async"},
    std::move(complete));
}

DoubleResult TwoStateDiscrete::try_read_value_precision_sync() const noexcept
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

double TwoStateDiscrete::read_value_precision_sync() const
{
  return ::ua::detail::good_value(try_read_value_precision_sync());
}

// --- Typed value write shortcuts ---

void TwoStateDiscrete::write_false_state_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::false_state_browse_name(),
    "TwoStateDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateDiscrete::try_write_false_state_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_false_state_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateDiscrete::write_false_state_sync(LocalizedText value) const
{
  try_write_false_state_sync(value).value();
}

void TwoStateDiscrete::write_true_state_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::true_state_browse_name(),
    "TwoStateDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateDiscrete::try_write_true_state_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_true_state_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateDiscrete::write_true_state_sync(LocalizedText value) const
{
  try_write_true_state_sync(value).value();
}

void TwoStateDiscrete::write_definition_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::definition_browse_name(),
    "TwoStateDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateDiscrete::try_write_definition_sync(String value) const noexcept
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

void TwoStateDiscrete::write_definition_sync(String value) const
{
  try_write_definition_sync(value).value();
}

void TwoStateDiscrete::write_value_precision_async(
  double value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateDiscreteTypeTraits::value_precision_browse_name(),
    "TwoStateDiscrete",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateDiscrete::try_write_value_precision_sync(double value) const noexcept
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

void TwoStateDiscrete::write_value_precision_sync(double value) const
{
  try_write_value_precision_sync(value).value();
}

}  // namespace ua
