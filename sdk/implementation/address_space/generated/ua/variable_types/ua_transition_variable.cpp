// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_transition_variable.h"

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

struct TransitionVariableTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{VariableTypeId::TransitionVariableType};
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

TransitionVariable::TransitionVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseDataVariable(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void TransitionVariable::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, VariableInstantiationAttributes attributes,
  CreateCompleteCallback complete) noexcept
{
  create_variable_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    TransitionVariableTypeTraits::type_definition_id(),
    std::move(options),
    std::move(attributes),
    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(TransitionVariableResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(TransitionVariableResult{
        TransitionVariable{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

TransitionVariableResult TransitionVariable::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionVariableResult>(addressSpace.executor(),
      [&](std::function<void(TransitionVariableResult)> complete)
      {
        TransitionVariable::create_async(
          std::move(addressSpace), parent, browseName, options, attributes, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TransitionVariable TransitionVariable::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  return ::ua::detail::good_value(
    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));
}

void TransitionVariable::create_async(AddressSpace addressSpace, const NodeId& parent,
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

void TransitionVariable::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // TransitionVariableType has subtypes - subtype match.
  instance_utils::attach_subtype_async(addressSpace,
    existingInstance,
    TransitionVariableTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(TransitionVariableResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(TransitionVariableResult{::ua::detail::address_space_gone("TransitionVariable")});
        return;
      }
      complete(TransitionVariable{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

TransitionVariableResult TransitionVariable::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<TransitionVariableResult>(addressSpace.executor(),
      [&](std::function<void(TransitionVariableResult)> complete)
      {
        TransitionVariable::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

TransitionVariable TransitionVariable::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void TransitionVariable::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void TransitionVariable::find_property_async(
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
    "TransitionVariable",
    std::move(complete));
}

// --- Property accessors ---

void TransitionVariable::id_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransitionVariableTypeTraits::id_browse_name(), std::move(complete));
}

PropertyResult TransitionVariable::try_id_property_sync() const noexcept
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

Property TransitionVariable::id_property_sync() const
{
  return ::ua::detail::good_value(try_id_property_sync());
}

void TransitionVariable::name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransitionVariableTypeTraits::name_browse_name(), std::move(complete));
}

PropertyResult TransitionVariable::try_name_property_sync() const noexcept
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

Property TransitionVariable::name_property_sync() const
{
  return ::ua::detail::good_value(try_name_property_sync());
}

void TransitionVariable::number_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransitionVariableTypeTraits::number_browse_name(), std::move(complete));
}

PropertyResult TransitionVariable::try_number_property_sync() const noexcept
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

Property TransitionVariable::number_property_sync() const
{
  return ::ua::detail::good_value(try_number_property_sync());
}

void TransitionVariable::transition_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(TransitionVariableTypeTraits::transition_time_browse_name(), std::move(complete));
}

PropertyResult TransitionVariable::try_transition_time_property_sync() const noexcept
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

Property TransitionVariable::transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_transition_time_property_sync());
}

void TransitionVariable::effective_transition_time_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    TransitionVariableTypeTraits::effective_transition_time_browse_name(), std::move(complete));
}

PropertyResult TransitionVariable::try_effective_transition_time_property_sync() const noexcept
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

Property TransitionVariable::effective_transition_time_property_sync() const
{
  return ::ua::detail::good_value(try_effective_transition_time_property_sync());
}

// --- Typed value read shortcuts ---

void TransitionVariable::read_name_async(std::function<void(QualifiedNameResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(QualifiedNameResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<QualifiedName>(*mAddressSpace,
    mNodeId,
    TransitionVariableTypeTraits::name_browse_name(),
    &Variant::is_qualified_name,
    {"TransitionVariable", "name", "TransitionVariable::read_name_async"},
    std::move(complete));
}

QualifiedNameResult TransitionVariable::try_read_name_sync() const noexcept
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

QualifiedName TransitionVariable::read_name_sync() const
{
  return ::ua::detail::good_value(try_read_name_sync());
}

void TransitionVariable::read_number_async(std::function<void(UInt32Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt32Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint32_t>(*mAddressSpace,
    mNodeId,
    TransitionVariableTypeTraits::number_browse_name(),
    &Variant::is_uint32,
    {"TransitionVariable", "number", "TransitionVariable::read_number_async"},
    std::move(complete));
}

UInt32Result TransitionVariable::try_read_number_sync() const noexcept
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

uint32_t TransitionVariable::read_number_sync() const
{
  return ::ua::detail::good_value(try_read_number_sync());
}

// --- Typed value write shortcuts ---

void TransitionVariable::write_name_async(
  QualifiedName value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TransitionVariableTypeTraits::name_browse_name(),
    "TransitionVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TransitionVariable::try_write_name_sync(QualifiedName value) const noexcept
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

void TransitionVariable::write_name_sync(QualifiedName value) const
{
  try_write_name_sync(value).value();
}

void TransitionVariable::write_number_async(
  uint32_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    TransitionVariableTypeTraits::number_browse_name(),
    "TransitionVariable",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult TransitionVariable::try_write_number_sync(uint32_t value) const noexcept
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

void TransitionVariable::write_number_sync(uint32_t value) const
{
  try_write_number_sync(value).value();
}

}  // namespace ua
