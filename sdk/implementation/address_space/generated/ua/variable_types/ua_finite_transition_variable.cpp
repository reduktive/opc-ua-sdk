// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_finite_transition_variable.h"

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

struct FiniteTransitionVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::FiniteTransitionVariableType};
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

  static QualifiedName transition_time_browse_name()
  {
    return QualifiedName{0, "TransitionTime"};
  }

  static QualifiedName effective_transition_time_browse_name()
  {
    return QualifiedName{0, "EffectiveTransitionTime"};
  }
};

}  // namespace

FiniteTransitionVariable::FiniteTransitionVariable(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void FiniteTransitionVariable::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    FiniteTransitionVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(FiniteTransitionVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(FiniteTransitionVariableResult{
        FiniteTransitionVariable{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

FiniteTransitionVariableResult FiniteTransitionVariable::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteTransitionVariableResult>(addressSpace.executor(),
      [&](std::function<void(FiniteTransitionVariableResult)> complete)
      {
        FiniteTransitionVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteTransitionVariable FiniteTransitionVariable::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void FiniteTransitionVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void FiniteTransitionVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // FiniteTransitionVariableType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    FiniteTransitionVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(FiniteTransitionVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          FiniteTransitionVariableResult{::ua::detail::address_space_gone("FiniteTransitionVariable")});
        return;
      }
      complete(
        FiniteTransitionVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

FiniteTransitionVariableResult FiniteTransitionVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FiniteTransitionVariableResult>(addressSpace.executor(),
      [&](std::function<void(FiniteTransitionVariableResult)> complete)
      {
        FiniteTransitionVariable::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

FiniteTransitionVariable FiniteTransitionVariable::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void FiniteTransitionVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void FiniteTransitionVariable::find_property_async(
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
    "FiniteTransitionVariable",
    std::move(complete));
}

// --- Property accessors ---

void FiniteTransitionVariable::id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteTransitionVariableTypeTraits::id_browse_name(), std::move(complete));
}

PropertyResult FiniteTransitionVariable::try_id_property_sync() const noexcept
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

Property FiniteTransitionVariable::id_property_sync() const
{
  return ::ua::detail::good_value(try_id_property_sync());
}

void FiniteTransitionVariable::name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteTransitionVariableTypeTraits::name_browse_name(), std::move(complete));
}

PropertyResult FiniteTransitionVariable::try_name_property_sync() const noexcept
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

Property FiniteTransitionVariable::name_property_sync() const
{
  return ::ua::detail::good_value(try_name_property_sync());
}

void FiniteTransitionVariable::number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteTransitionVariableTypeTraits::number_browse_name(), std::move(complete));
}

PropertyResult FiniteTransitionVariable::try_number_property_sync() const noexcept
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

Property FiniteTransitionVariable::number_property_sync() const
{
  return ::ua::detail::good_value(try_number_property_sync());
}

void FiniteTransitionVariable::transition_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(FiniteTransitionVariableTypeTraits::transition_time_browse_name(), std::move(complete));
}

PropertyResult FiniteTransitionVariable::try_transition_time_property_sync() const noexcept
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

Property FiniteTransitionVariable::transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_transition_time_property_sync());
}

void FiniteTransitionVariable::effective_transition_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    FiniteTransitionVariableTypeTraits::effective_transition_time_browse_name(), std::move(complete));
}

PropertyResult FiniteTransitionVariable::try_effective_transition_time_property_sync() const noexcept
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

Property FiniteTransitionVariable::effective_transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_effective_transition_time_property_sync());
}

// --- Typed value read shortcuts ---

void FiniteTransitionVariable::read_id_async(std::function<void(NodeIdResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NodeIdResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<NodeId>(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::id_browse_name(),
    &Variant::is_node_id,
    {"FiniteTransitionVariable", "id", "FiniteTransitionVariable::read_id_async"},
    std::move(complete));
}

NodeIdResult FiniteTransitionVariable::try_read_id_sync() const noexcept
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

NodeId FiniteTransitionVariable::read_id_sync() const
{
  return ::ua::detail::good_value(try_read_id_sync());
}

void FiniteTransitionVariable::read_name_async(
  std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::name_browse_name(),
    &Variant::is_qualified_name,
    {"FiniteTransitionVariable", "name", "FiniteTransitionVariable::read_name_async"},
    std::move(complete));
}

QualifiedNameResult FiniteTransitionVariable::try_read_name_sync() const noexcept
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

QualifiedName FiniteTransitionVariable::read_name_sync() const
{
  return ::ua::detail::good_value(try_read_name_sync());
}

void FiniteTransitionVariable::read_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::number_browse_name(),
    &Variant::is_uint32,
    {"FiniteTransitionVariable", "number", "FiniteTransitionVariable::read_number_async"},
    std::move(complete));
}

UInt32Result FiniteTransitionVariable::try_read_number_sync() const noexcept
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

uint32_t FiniteTransitionVariable::read_number_sync() const
{
  return ::ua::detail::good_value(try_read_number_sync());
}

// --- Typed value write shortcuts ---

void FiniteTransitionVariable::write_id_async(
  NodeId value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::id_browse_name(),
    "FiniteTransitionVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteTransitionVariable::try_write_id_sync(NodeId value) const noexcept
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

void FiniteTransitionVariable::write_id_sync(NodeId value) const
{
  try_write_id_sync(value).value();
}

void FiniteTransitionVariable::write_name_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::name_browse_name(),
    "FiniteTransitionVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteTransitionVariable::try_write_name_sync(QualifiedName value) const noexcept
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

void FiniteTransitionVariable::write_name_sync(QualifiedName value) const
{
  try_write_name_sync(value).value();
}

void FiniteTransitionVariable::write_number_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    FiniteTransitionVariableTypeTraits::number_browse_name(),
    "FiniteTransitionVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult FiniteTransitionVariable::try_write_number_sync(uint32_t value) const noexcept
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

void FiniteTransitionVariable::write_number_sync(uint32_t value) const
{
  try_write_number_sync(value).value();
}

}  // namespace ua
