// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_variable.h"

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

struct StateVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::StateVariableType};
  }

  static QualifiedName id_browse_name()
  {
    return QualifiedName{0, "Id"};
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

StateVariable::StateVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void StateVariable::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    StateVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(StateVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(StateVariableResult{
        StateVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

StateVariableResult StateVariable::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateVariableResult>(addressSpace.executor(),
      [&](std::function<void(StateVariableResult)> complete)
      {
        StateVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StateVariable StateVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void StateVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void StateVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // StateVariableType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    StateVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(StateVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(StateVariableResult{::ua::detail::address_space_gone("StateVariable")});
        return;
      }
      complete(StateVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

StateVariableResult StateVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StateVariableResult>(addressSpace.executor(),
      [&](std::function<void(StateVariableResult)> complete)
      {
        StateVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StateVariable StateVariable::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void StateVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void StateVariable::find_property_async(
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
    "StateVariable",
    std::move(complete));
}

// --- Property accessors ---

void StateVariable::id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(StateVariableTypeTraits::id_browse_name(), std::move(complete));
}

PropertyResult StateVariable::try_id_property_sync() const noexcept
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

Property StateVariable::id_property_sync() const
{
  return ::ua::detail::good_value(try_id_property_sync());
}

void StateVariable::name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(StateVariableTypeTraits::name_browse_name(), std::move(complete));
}

PropertyResult StateVariable::try_name_property_sync() const noexcept
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

Property StateVariable::name_property_sync() const
{
  return ::ua::detail::good_value(try_name_property_sync());
}

void StateVariable::number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(StateVariableTypeTraits::number_browse_name(), std::move(complete));
}

PropertyResult StateVariable::try_number_property_sync() const noexcept
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

Property StateVariable::number_property_sync() const
{
  return ::ua::detail::good_value(try_number_property_sync());
}

void StateVariable::effective_display_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(StateVariableTypeTraits::effective_display_name_browse_name(), std::move(complete));
}

PropertyResult StateVariable::try_effective_display_name_property_sync() const noexcept
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

Property StateVariable::effective_display_name_property_sync() const
{
  return ::ua::detail::good_value(try_effective_display_name_property_sync());
}

// --- Typed value read shortcuts ---

void StateVariable::read_name_async(std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::name_browse_name(),
    &Variant::is_qualified_name,
    {"StateVariable", "name", "StateVariable::read_name_async"},
    std::move(complete));
}

QualifiedNameResult StateVariable::try_read_name_sync() const noexcept
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

QualifiedName StateVariable::read_name_sync() const
{
  return ::ua::detail::good_value(try_read_name_sync());
}

void StateVariable::read_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::number_browse_name(),
    &Variant::is_uint32,
    {"StateVariable", "number", "StateVariable::read_number_async"},
    std::move(complete));
}

UInt32Result StateVariable::try_read_number_sync() const noexcept
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

uint32_t StateVariable::read_number_sync() const
{
  return ::ua::detail::good_value(try_read_number_sync());
}

void StateVariable::read_effective_display_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::effective_display_name_browse_name(),
    &Variant::is_localized_text,
    {"StateVariable", "effective_display_name", "StateVariable::read_effective_display_name_async"},
    std::move(complete));
}

LocalizedTextResult StateVariable::try_read_effective_display_name_sync() const noexcept
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

LocalizedText StateVariable::read_effective_display_name_sync() const
{
  return ::ua::detail::good_value(try_read_effective_display_name_sync());
}

// --- Typed value write shortcuts ---

void StateVariable::write_name_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::name_browse_name(),
    "StateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult StateVariable::try_write_name_sync(QualifiedName value) const noexcept
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

void StateVariable::write_name_sync(QualifiedName value) const
{
  try_write_name_sync(value).value();
}

void StateVariable::write_number_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::number_browse_name(),
    "StateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult StateVariable::try_write_number_sync(uint32_t value) const noexcept
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

void StateVariable::write_number_sync(uint32_t value) const
{
  try_write_number_sync(value).value();
}

void StateVariable::write_effective_display_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    StateVariableTypeTraits::effective_display_name_browse_name(),
    "StateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult StateVariable::try_write_effective_display_name_sync(LocalizedText value) const noexcept
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

void StateVariable::write_effective_display_name_sync(LocalizedText value) const
{
  try_write_effective_display_name_sync(value).value();
}

}  // namespace ua
