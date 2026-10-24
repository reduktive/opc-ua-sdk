// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_finite_state_variable.h"

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

struct FiniteStateVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::FiniteStateVariableType};
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

FiniteStateVariable::FiniteStateVariable(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void FiniteStateVariable::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    FiniteStateVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(FiniteStateVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(FiniteStateVariableResult{
        FiniteStateVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

FiniteStateVariableResult FiniteStateVariable::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(FiniteStateVariableResult)> complete)
      {
        FiniteStateVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteStateVariable FiniteStateVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void FiniteStateVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void FiniteStateVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // FiniteStateVariableType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    FiniteStateVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(FiniteStateVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(FiniteStateVariableResult{::ua::detail::address_space_gone("FiniteStateVariable")});
        return;
      }
      complete(
        FiniteStateVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

FiniteStateVariableResult FiniteStateVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteStateVariableResult>(addressSpace.executor(),
      [&](std::function<void(FiniteStateVariableResult)> complete)
      {
        FiniteStateVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteStateVariable FiniteStateVariable::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void FiniteStateVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void FiniteStateVariable::find_property_async(
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
    "FiniteStateVariable",
    std::move(complete));
}

// --- Property accessors ---

void FiniteStateVariable::id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteStateVariableTypeTraits::id_browse_name(), std::move(complete));
}

PropertyResult FiniteStateVariable::try_id_property_sync() const noexcept
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

Property FiniteStateVariable::id_property_sync() const
{
  return ::ua::detail::good_value(try_id_property_sync());
}

void FiniteStateVariable::name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteStateVariableTypeTraits::name_browse_name(), std::move(complete));
}

PropertyResult FiniteStateVariable::try_name_property_sync() const noexcept
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

Property FiniteStateVariable::name_property_sync() const
{
  return ::ua::detail::good_value(try_name_property_sync());
}

void FiniteStateVariable::number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteStateVariableTypeTraits::number_browse_name(), std::move(complete));
}

PropertyResult FiniteStateVariable::try_number_property_sync() const noexcept
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

Property FiniteStateVariable::number_property_sync() const
{
  return ::ua::detail::good_value(try_number_property_sync());
}

void FiniteStateVariable::effective_display_name_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    FiniteStateVariableTypeTraits::effective_display_name_browse_name(), std::move(complete));
}

PropertyResult FiniteStateVariable::try_effective_display_name_property_sync() const noexcept
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

Property FiniteStateVariable::effective_display_name_property_sync() const
{
  return ::ua::detail::good_value(try_effective_display_name_property_sync());
}

// --- Typed value read shortcuts ---

void FiniteStateVariable::read_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::id_browse_name(),
    &Variant::is_node_id,
    {"FiniteStateVariable", "id", "FiniteStateVariable::read_id_async"},
    std::move(complete));
}

NodeIdResult FiniteStateVariable::try_read_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NodeIdResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NodeIdResult)> complete) { read_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

NodeId FiniteStateVariable::read_id_sync() const
{
  return ::ua::detail::good_value(try_read_id_sync());
}

void FiniteStateVariable::read_name_async(std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::name_browse_name(),
    &Variant::is_qualified_name,
    {"FiniteStateVariable", "name", "FiniteStateVariable::read_name_async"},
    std::move(complete));
}

QualifiedNameResult FiniteStateVariable::try_read_name_sync() const noexcept
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

QualifiedName FiniteStateVariable::read_name_sync() const
{
  return ::ua::detail::good_value(try_read_name_sync());
}

void FiniteStateVariable::read_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::number_browse_name(),
    &Variant::is_uint32,
    {"FiniteStateVariable", "number", "FiniteStateVariable::read_number_async"},
    std::move(complete));
}

UInt32Result FiniteStateVariable::try_read_number_sync() const noexcept
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

uint32_t FiniteStateVariable::read_number_sync() const
{
  return ::ua::detail::good_value(try_read_number_sync());
}

void FiniteStateVariable::read_effective_display_name_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::effective_display_name_browse_name(),
    &Variant::is_localized_text,
    {"FiniteStateVariable",
      "effective_display_name",
      "FiniteStateVariable::read_effective_display_name_async"},
    std::move(complete));
}

LocalizedTextResult FiniteStateVariable::try_read_effective_display_name_sync() const noexcept
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

LocalizedText FiniteStateVariable::read_effective_display_name_sync() const
{
  return ::ua::detail::good_value(try_read_effective_display_name_sync());
}

// --- Typed value write shortcuts ---

void FiniteStateVariable::write_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::id_browse_name(),
    "FiniteStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteStateVariable::try_write_id_sync(NodeId value) const noexcept
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

void FiniteStateVariable::write_id_sync(NodeId value) const
{
  try_write_id_sync(value).value();
}

void FiniteStateVariable::write_name_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::name_browse_name(),
    "FiniteStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteStateVariable::try_write_name_sync(QualifiedName value) const noexcept
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

void FiniteStateVariable::write_name_sync(QualifiedName value) const
{
  try_write_name_sync(value).value();
}

void FiniteStateVariable::write_number_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::number_browse_name(),
    "FiniteStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteStateVariable::try_write_number_sync(uint32_t value) const noexcept
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

void FiniteStateVariable::write_number_sync(uint32_t value) const
{
  try_write_number_sync(value).value();
}

void FiniteStateVariable::write_effective_display_name_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteStateVariableTypeTraits::effective_display_name_browse_name(),
    "FiniteStateVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteStateVariable::try_write_effective_display_name_sync(LocalizedText value) const noexcept
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

void FiniteStateVariable::write_effective_display_name_sync(LocalizedText value) const
{
  try_write_effective_display_name_sync(value).value();
}

}  // namespace ua
