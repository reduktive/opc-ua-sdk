// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_two_state_variable.h"

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

struct TwoStateVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::TwoStateVariableType};
  }

  static QualifiedName id_browse_name()
  {
    return QualifiedName{0, "Id"};
  }

  static QualifiedName transition_time_browse_name()
  {
    return QualifiedName{0, "TransitionTime"};
  }

  static QualifiedName effective_transition_time_browse_name()
  {
    return QualifiedName{0, "EffectiveTransitionTime"};
  }

  static QualifiedName true_state_browse_name()
  {
    return QualifiedName{0, "TrueState"};
  }

  static QualifiedName false_state_browse_name()
  {
    return QualifiedName{0, "FalseState"};
  }

  static QualifiedName name_browse_name()
  {
    return QualifiedName{0, "Name"};
  }

  static QualifiedName number_browse_name()
  {
    return QualifiedName{0, "Number"};
  }

  static QualifiedName effective_display_name_browse_name()
  {
    return QualifiedName{0, "EffectiveDisplayName"};
  }
};

}  // namespace

TwoStateVariable::TwoStateVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TwoStateVariable::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TwoStateVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TwoStateVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TwoStateVariableResult{
        TwoStateVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

TwoStateVariableResult TwoStateVariable::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(TwoStateVariableResult)> complete)
      {
        TwoStateVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable TwoStateVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void TwoStateVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void TwoStateVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TwoStateVariableType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    TwoStateVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TwoStateVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TwoStateVariableResult{::ua::detail::address_space_gone("TwoStateVariable")});
        return;
      }
      complete(TwoStateVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TwoStateVariableResult TwoStateVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TwoStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(TwoStateVariableResult)> complete)
      {
        TwoStateVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TwoStateVariable TwoStateVariable::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TwoStateVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void TwoStateVariable::find_property_async(
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
    "TwoStateVariable",
    std::move(complete));
}

// --- Property accessors ---

void TwoStateVariable::id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::id_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::id_property_sync() const
{
  return ::ua::detail::good_value(try_id_property_sync());
}

void TwoStateVariable::transition_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::transition_time_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_transition_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { transition_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_transition_time_property_sync());
}

void TwoStateVariable::effective_transition_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    TwoStateVariableTypeTraits::effective_transition_time_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_effective_transition_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { effective_transition_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::effective_transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_effective_transition_time_property_sync());
}

void TwoStateVariable::true_state_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::true_state_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_true_state_property_sync() const noexcept
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

Property TwoStateVariable::true_state_property_sync() const
{
  return ::ua::detail::good_value(try_true_state_property_sync());
}

void TwoStateVariable::false_state_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::false_state_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_false_state_property_sync() const noexcept
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

Property TwoStateVariable::false_state_property_sync() const
{
  return ::ua::detail::good_value(try_false_state_property_sync());
}

void TwoStateVariable::name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::name_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::name_property_sync() const
{
  return ::ua::detail::good_value(try_name_property_sync());
}

void TwoStateVariable::number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::number_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_number_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { number_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::number_property_sync() const
{
  return ::ua::detail::good_value(try_number_property_sync());
}

void TwoStateVariable::effective_display_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TwoStateVariableTypeTraits::effective_display_name_browse_name(), std::move(complete));
}

PropertyResult TwoStateVariable::try_effective_display_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { effective_display_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property TwoStateVariable::effective_display_name_property_sync() const
{
  return ::ua::detail::good_value(try_effective_display_name_property_sync());
}

// --- Typed value read shortcuts ---

void TwoStateVariable::read_id_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::id_browse_name(),
    &Variant::is_boolean,
    {"TwoStateVariable", "id", "TwoStateVariable::read_id_async"},
    std::move(complete));
}

BoolResult TwoStateVariable::try_read_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool TwoStateVariable::read_id_sync() const
{
  return ::ua::detail::good_value(try_read_id_sync());
}

void TwoStateVariable::read_true_state_async(std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::true_state_browse_name(),
    &Variant::is_localized_text,
    {"TwoStateVariable", "true_state", "TwoStateVariable::read_true_state_async"},
    std::move(complete));
}

LocalizedTextResult TwoStateVariable::try_read_true_state_sync() const noexcept
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

LocalizedText TwoStateVariable::read_true_state_sync() const
{
  return ::ua::detail::good_value(try_read_true_state_sync());
}

void TwoStateVariable::read_false_state_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::false_state_browse_name(),
    &Variant::is_localized_text,
    {"TwoStateVariable", "false_state", "TwoStateVariable::read_false_state_async"},
    std::move(complete));
}

LocalizedTextResult TwoStateVariable::try_read_false_state_sync() const noexcept
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

LocalizedText TwoStateVariable::read_false_state_sync() const
{
  return ::ua::detail::good_value(try_read_false_state_sync());
}

void TwoStateVariable::read_name_async(std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::name_browse_name(),
    &Variant::is_qualified_name,
    {"TwoStateVariable", "name", "TwoStateVariable::read_name_async"},
    std::move(complete));
}

QualifiedNameResult TwoStateVariable::try_read_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<QualifiedNameResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(QualifiedNameResult)> complete) { read_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

QualifiedName TwoStateVariable::read_name_sync() const
{
  return ::ua::detail::good_value(try_read_name_sync());
}

void TwoStateVariable::read_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::number_browse_name(),
    &Variant::is_uint32,
    {"TwoStateVariable", "number", "TwoStateVariable::read_number_async"},
    std::move(complete));
}

UInt32Result TwoStateVariable::try_read_number_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt32Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt32Result)> complete) { read_number_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint32_t TwoStateVariable::read_number_sync() const
{
  return ::ua::detail::good_value(try_read_number_sync());
}

void TwoStateVariable::read_effective_display_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::effective_display_name_browse_name(),
    &Variant::is_localized_text,
    {"TwoStateVariable", "effective_display_name", "TwoStateVariable::read_effective_display_name_async"},
    std::move(complete));
}

LocalizedTextResult TwoStateVariable::try_read_effective_display_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_effective_display_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText TwoStateVariable::read_effective_display_name_sync() const
{
  return ::ua::detail::good_value(try_read_effective_display_name_sync());
}

// --- Typed value write shortcuts ---

void TwoStateVariable::write_id_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::id_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_id_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateVariable::write_id_sync(bool value) const
{
  try_write_id_sync(value).value();
}

void TwoStateVariable::write_true_state_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::true_state_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_true_state_sync(LocalizedText value) const noexcept
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

void TwoStateVariable::write_true_state_sync(LocalizedText value) const
{
  try_write_true_state_sync(value).value();
}

void TwoStateVariable::write_false_state_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::false_state_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_false_state_sync(LocalizedText value) const noexcept
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

void TwoStateVariable::write_false_state_sync(LocalizedText value) const
{
  try_write_false_state_sync(value).value();
}

void TwoStateVariable::write_name_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::name_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_name_sync(QualifiedName value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateVariable::write_name_sync(QualifiedName value) const
{
  try_write_name_sync(value).value();
}

void TwoStateVariable::write_number_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::number_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_number_sync(uint32_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_number_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateVariable::write_number_sync(uint32_t value) const
{
  try_write_number_sync(value).value();
}

void TwoStateVariable::write_effective_display_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TwoStateVariableTypeTraits::effective_display_name_browse_name(),
    "TwoStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TwoStateVariable::try_write_effective_display_name_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_effective_display_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void TwoStateVariable::write_effective_display_name_sync(LocalizedText value) const
{
  try_write_effective_display_name_sync(value).value();
}

}  // namespace ua
